
#define _POSIX_C_SOURCE 200809L
#include <microhttpd.h>
#include <sqlite3.h>
#include <jansson.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define BODY_LIMIT (2 * 1024 * 1024)
#define AVATAR_LIMIT (1024 * 1024)
#define POST_BODY_LIMIT 4000
#define COMMENT_BODY_LIMIT 1000
#define COOKIE_NAME "wb_session"
#define RATE_LIMIT_BUCKETS 512

typedef struct {
    char key[192];
    time_t window_start;
    time_t last_seen;
    unsigned int count;
} RateLimitBucket;

typedef struct {
    char bind[64];
    uint16_t port;
    char web_root[PATH_MAX];
    char uploads_root[PATH_MAX];
    char export_json_path[PATH_MAX];
    char schema_path[PATH_MAX];
    char admin_seed_path[PATH_MAX];
    char db_path[PATH_MAX];
    char admin_email[256];
    char admin_password[256];
    char admin_username[128];
    char github_token[256];
    char allowed_origins[1024];
    char cookie_domain[256];
    char smtp_url[512];
    char smtp_username[256];
    char smtp_password[256];
    char smtp_from[256];
    char smtp_from_name[128];
    int cookie_secure;
    int star_cache_seconds;
} AppConfig;

typedef struct {
    char *body;
    size_t body_len;
    int processed;
} ConnectionInfo;

typedef struct { char *data; size_t len; } Buffer;
typedef struct { const char *data; size_t len; size_t pos; } UploadBuffer;

typedef struct {
    int64_t id;
    char uid[16];
    char username[128];
    char email[256];
    char role[16];
    bool muted;
    char avatar_data_url[700000];
} SessionUser;

static AppConfig g_cfg;
static RateLimitBucket g_rate_limits[RATE_LIMIT_BUCKETS];
static pthread_mutex_t g_rate_limit_lock = PTHREAD_MUTEX_INITIALIZER;

static enum MHD_Result serve_binary_file(struct MHD_Connection *connection, const char *path);
static enum MHD_Result handle_api_me(struct MHD_Connection *connection);
static json_t *user_json_minimal(const SessionUser *su);
static json_t *board_posts_json(sqlite3 *db, int64_t viewer_id, bool viewer_is_admin);
static json_t *comments_json_for_post(sqlite3 *db, int64_t post_id, int64_t viewer_id, bool viewer_is_admin);
static json_t *reactions_json_for_target(sqlite3 *db, const char *target_type, int64_t target_id, int64_t viewer_id);
static bool db_prepare(sqlite3 *db, sqlite3_stmt **stmt, const char *sql);
static void db_bind_text(sqlite3_stmt *stmt, int idx, const char *value);
static void db_bind_int64(sqlite3_stmt *stmt, int idx, int64_t v);
static bool db_step_ok(sqlite3 *db, sqlite3_stmt *stmt);

static void log_error(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); fprintf(stderr, "[warehouse-blog] "); vfprintf(stderr, fmt, ap); fputc('\n', stderr); va_end(ap);
}
static void die(const char *fmt, ...) {
    va_list ap; va_start(ap, fmt); fprintf(stderr, "[warehouse-blog] "); vfprintf(stderr, fmt, ap); fputc('\n', stderr); va_end(ap); exit(EXIT_FAILURE);
}
static void str_copy(char *dst, size_t cap, const char *src) {
    if (!dst || cap == 0) {
        return;
    }
    const char *in = src ? src : "";
    size_t n = strlen(in);
    if (n >= cap) {
        n = cap - 1;
    }
    memcpy(dst, in, n);
    dst[n] = '\0';
}
static const char *env_or(const char *name, const char *fallback) {
    const char *v = getenv(name); return (v && *v) ? v : fallback;
}
static void mkdir_p(const char *path) {
    char tmp[PATH_MAX]; str_copy(tmp, sizeof(tmp), path); size_t len = strlen(tmp); if (!len) return; if (tmp[len-1] == '/') tmp[len-1] = '\0';
    for (char *p = tmp + 1; *p; ++p) { if (*p == '/') { *p='\0'; if (mkdir(tmp,0755) != 0 && errno != EEXIST) die("mkdir(%s) failed: %s", tmp, strerror(errno)); *p='/'; } }
    if (mkdir(tmp,0755) != 0 && errno != EEXIST) die("mkdir(%s) failed: %s", tmp, strerror(errno));
}
static char *read_file_text(const char *path, size_t *out_len) {
    FILE *fp = fopen(path, "rb"); if (!fp) return NULL; if (fseek(fp,0,SEEK_END)!=0){ fclose(fp); return NULL; } long sz = ftell(fp); if (sz < 0){ fclose(fp); return NULL; } rewind(fp);
    char *buf = calloc((size_t)sz + 1, 1); if (!buf){ fclose(fp); return NULL; }
    size_t n = fread(buf,1,(size_t)sz,fp); fclose(fp); if (n != (size_t)sz){ free(buf); return NULL; } if (out_len) *out_len=n; return buf;
}
static bool write_text_file(const char *path, const char *text) {
    FILE *fp = fopen(path, "wb"); if (!fp) return false; size_t n = fwrite(text,1,strlen(text),fp); fclose(fp); return n == strlen(text);
}
static void load_config(void) {
    str_copy(g_cfg.bind, sizeof(g_cfg.bind), env_or("WB_BIND", "127.0.0.1"));
    g_cfg.port = (uint16_t) strtoul(env_or("WB_PORT", "8080"), NULL, 10);
    str_copy(g_cfg.web_root, sizeof(g_cfg.web_root), env_or("WB_WEB_ROOT", "./web"));
    str_copy(g_cfg.uploads_root, sizeof(g_cfg.uploads_root), env_or("WB_UPLOADS_ROOT", "./data/uploads/avatars"));
    str_copy(g_cfg.export_json_path, sizeof(g_cfg.export_json_path), env_or("WB_EXPORT_JSON", "./data/export/site-state.json"));
    str_copy(g_cfg.schema_path, sizeof(g_cfg.schema_path), env_or("WB_SCHEMA_PATH", "./backend/sql/schema.sql"));
    str_copy(g_cfg.admin_seed_path, sizeof(g_cfg.admin_seed_path), env_or("WB_ADMIN_SEED_PATH", "./data/admin-seed.json"));
    str_copy(g_cfg.db_path, sizeof(g_cfg.db_path), env_or("WB_DB_PATH", "./data/warehouse-blog.sqlite3"));
    str_copy(g_cfg.admin_email, sizeof(g_cfg.admin_email), env_or("WB_ADMIN_EMAIL", "admin@example.com"));
    str_copy(g_cfg.admin_password, sizeof(g_cfg.admin_password), env_or("WB_ADMIN_PASSWORD", "PleaseChangeMe123!"));
    str_copy(g_cfg.admin_username, sizeof(g_cfg.admin_username), env_or("WB_ADMIN_USERNAME", "Site Admin"));
    str_copy(g_cfg.github_token, sizeof(g_cfg.github_token), env_or("WB_GITHUB_TOKEN", ""));
    str_copy(g_cfg.allowed_origins, sizeof(g_cfg.allowed_origins), env_or("WB_ALLOWED_ORIGINS", "https://your-frontend-domain.example,http://IP:8080,http://localhost:8080"));
    str_copy(g_cfg.cookie_domain, sizeof(g_cfg.cookie_domain), env_or("WB_COOKIE_DOMAIN", ""));
    str_copy(g_cfg.smtp_url, sizeof(g_cfg.smtp_url), env_or("WB_SMTP_URL", ""));
    str_copy(g_cfg.smtp_username, sizeof(g_cfg.smtp_username), env_or("WB_SMTP_USERNAME", ""));
    str_copy(g_cfg.smtp_password, sizeof(g_cfg.smtp_password), env_or("WB_SMTP_PASSWORD", ""));
    str_copy(g_cfg.smtp_from, sizeof(g_cfg.smtp_from), env_or("WB_SMTP_FROM", ""));
    str_copy(g_cfg.smtp_from_name, sizeof(g_cfg.smtp_from_name), env_or("WB_SMTP_FROM_NAME", "Warehouse-Blog"));
    g_cfg.cookie_secure = atoi(env_or("WB_COOKIE_SECURE", "0"));
    g_cfg.star_cache_seconds = atoi(env_or("WB_STAR_CACHE_SECONDS", "30"));
    if (g_cfg.star_cache_seconds <= 0) g_cfg.star_cache_seconds = 30;
}
static char *normalize_email(const char *email) {
    if (!email) {
        return strdup("");
    }
    size_t len = strlen(email);
    char *out = calloc(len + 1, 1);
    if (!out) {
        return NULL;
    }
    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char) email[i];
        if (isspace(c)) {
            continue;
        }
        out[j++] = (char) tolower(c);
    }
    out[j] = '\0';
    return out;
}
static bool valid_email(const char *email) {
    if (!email || !*email) {
        return false;
    }
    const char *at = strchr(email, '@');
    if (!at || at == email) {
        return false;
    }
    const char *dot = strrchr(at + 1, '.');
    return dot && dot[1] != '\0';
}
static bool is_configured_admin_email(const char *normalized_email) {
    char *admin_email_norm = normalize_email(g_cfg.admin_email);
    bool match = admin_email_norm && normalized_email && strcmp(normalized_email, admin_email_norm) == 0;
    free(admin_email_norm);
    return match;
}
static bool valid_repo_name(const char *repo) {
    if (!repo || !*repo) {
        return false;
    }
    bool slash = false;
    for (const unsigned char *p = (const unsigned char *) repo; *p; ++p) {
        unsigned char c = *p;
        if (isalnum(c) || c == '_' || c == '-' || c == '.') {
            continue;
        }
        if (c == '/') {
            if (slash) {
                return false;
            }
            slash = true;
            continue;
        }
        return false;
    }
    return slash;
}
static bool parse_repo_input(const char *input, char *owner, size_t owner_cap, char *repo, size_t repo_cap, char *full, size_t full_cap, char *url, size_t url_cap) {
    if (!input) {
        return false;
    }
    char work[512];
    str_copy(work, sizeof(work), input);
    char *trim = work;
    while (*trim && isspace((unsigned char) *trim)) {
        ++trim;
    }
    char *end = trim + strlen(trim);
    while (end > trim && isspace((unsigned char) end[-1])) {
        --end;
    }
    *end = '\0';
    if (!*trim) {
        return false;
    }

    char owner_repo[256] = {0};
    if (strncasecmp(trim, "git@github.com:", 15) == 0) {
        str_copy(owner_repo, sizeof(owner_repo), trim + 15);
    } else if (strncasecmp(trim, "github.com/", 11) == 0) {
        str_copy(owner_repo, sizeof(owner_repo), trim + 11);
    } else if (strncasecmp(trim, "www.github.com/", 15) == 0) {
        str_copy(owner_repo, sizeof(owner_repo), trim + 15);
    } else if (strncasecmp(trim, "http://", 7) == 0 || strncasecmp(trim, "https://", 8) == 0) {
        const char *p = strstr(trim, "://");
        p = p ? p + 3 : trim;
        const char *host_start = p;
        const char *path = strchr(host_start, '/');
        if (!path) {
            return false;
        }
        size_t host_len = (size_t) (path - host_start);
        char host[64] = {0};
        if (host_len == 0 || host_len >= sizeof(host)) {
            return false;
        }
        memcpy(host, host_start, host_len);
        host[host_len] = '\0';
        if (strcasecmp(host, "github.com") != 0 && strcasecmp(host, "www.github.com") != 0) {
            return false;
        }
        ++path;
        const char *slash2 = strchr(path, '/');
        if (!slash2) {
            return false;
        }
        size_t a = (size_t) (slash2 - path);
        if (a >= sizeof(owner_repo) - 2) {
            return false;
        }
        memcpy(owner_repo, path, a);
        owner_repo[a] = '/';
        const char *p2 = slash2 + 1;
        const char *slash3 = strchr(p2, '/');
        size_t b = slash3 ? (size_t) (slash3 - p2) : strlen(p2);
        if (a + 1 + b >= sizeof(owner_repo)) {
            return false;
        }
        memcpy(owner_repo + a + 1, p2, b);
        owner_repo[a + 1 + b] = '\0';
    } else {
        str_copy(owner_repo, sizeof(owner_repo), trim);
    }

    size_t start = 0;
    size_t current_len = strlen(owner_repo);
    while (start < current_len && owner_repo[start] == '/') {
        ++start;
    }
    if (start > 0) {
        memmove(owner_repo, owner_repo + start, current_len - start + 1);
    }
    current_len = strlen(owner_repo);
    while (current_len > 0 && owner_repo[current_len - 1] == '/') {
        owner_repo[current_len - 1] = '\0';
        --current_len;
    }
    if (current_len > 4 && strcmp(owner_repo + current_len - 4, ".git") == 0) {
        owner_repo[current_len - 4] = '\0';
    }
    if (!valid_repo_name(owner_repo)) {
        return false;
    }
    char *slash = strchr(owner_repo, '/');
    if (!slash) {
        return false;
    }
    *slash = '\0';
    str_copy(owner, owner_cap, owner_repo);
    str_copy(repo, repo_cap, slash + 1);
    snprintf(full, full_cap, "%s/%s", owner, repo);
    snprintf(url, url_cap, "https://github.com/%s/%s", owner, repo);
    return true;
}
static bool hash_sha256_hex(const char *input, char out_hex[65]) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new(); if (!ctx) return false; unsigned char md[EVP_MAX_MD_SIZE]; unsigned int md_len=0;
    bool ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 && EVP_DigestUpdate(ctx, input, strlen(input)) == 1 && EVP_DigestFinal_ex(ctx, md, &md_len) == 1;
    EVP_MD_CTX_free(ctx); if (!ok || md_len != 32) return false; for (unsigned int i=0;i<md_len;++i) snprintf(out_hex+i*2, 3, "%02x", md[i]); out_hex[64]='\0'; return true;
}
static char *generate_session_id(void) {
    unsigned char bytes[32]; if (RAND_bytes(bytes, (int)sizeof(bytes)) != 1) return NULL; char *out = calloc(65,1); if(!out) return NULL; for(size_t i=0;i<sizeof(bytes);++i) snprintf(out+i*2,3,"%02x",bytes[i]); return out;
}
static bool generate_verification_code(char out[7]) {
    unsigned int value = 0;
    if (RAND_bytes((unsigned char *) &value, sizeof(value)) != 1) {
        value = (unsigned int) rand();
    }
    snprintf(out, 7, "%06u", value % 1000000u);
    return true;
}
static time_t now_epoch(void) { return time(NULL); }
static bool db_exec_sql_ignore(sqlite3 *db, const char *sql) {
    char *errmsg = NULL;
    int rc = sqlite3_exec(db, sql, NULL, NULL, &errmsg);
    if (rc != SQLITE_OK) {
        sqlite3_free(errmsg);
        return false;
    }
    return true;
}
static bool uid_exists(sqlite3 *db, const char *uid, int64_t exclude_id) {
    sqlite3_stmt *stmt = NULL;
    bool exists = false;
    if (exclude_id > 0) {
        if (db_prepare(db, &stmt, "SELECT 1 FROM app_users WHERE uid=? AND id<>? LIMIT 1")) {
            db_bind_text(stmt, 1, uid);
            db_bind_int64(stmt, 2, exclude_id);
            exists = sqlite3_step(stmt) == SQLITE_ROW;
            sqlite3_finalize(stmt);
        }
    } else {
        if (db_prepare(db, &stmt, "SELECT 1 FROM app_users WHERE uid=? LIMIT 1")) {
            db_bind_text(stmt, 1, uid);
            exists = sqlite3_step(stmt) == SQLITE_ROW;
            sqlite3_finalize(stmt);
        }
    }
    return exists;
}
static bool generate_unique_uid(sqlite3 *db, char out[16]) {
    for (int i = 0; i < 256; ++i) {
        unsigned int value = 0;
        if (RAND_bytes((unsigned char *) &value, sizeof(value)) != 1) {
            value = (unsigned int) rand();
        }
        value = (value % 99999999u) + 1u;
        char uidbuf[16];
        snprintf(uidbuf, sizeof(uidbuf), "%u", value);
        if (!uid_exists(db, uidbuf, 0)) {
            str_copy(out, 16, uidbuf);
            return true;
        }
    }
    return false;
}
static int64_t user_id_by_uid(sqlite3 *db, const char *uid) {
    sqlite3_stmt *stmt = NULL;
    int64_t user_id = 0;
    if (db_prepare(db, &stmt, "SELECT id FROM app_users WHERE uid=? LIMIT 1")) {
        db_bind_text(stmt, 1, uid);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            user_id = sqlite3_column_int64(stmt, 0);
        }
        sqlite3_finalize(stmt);
    }
    return user_id;
}
static bool ensure_schema_migrations(sqlite3 *db) {
    if (!db_exec_sql_ignore(db, "ALTER TABLE app_users ADD COLUMN uid TEXT NOT NULL DEFAULT ''")) {}
    if (!db_exec_sql_ignore(db, "ALTER TABLE app_users ADD COLUMN muted INTEGER NOT NULL DEFAULT 0")) {}
    db_exec_sql_ignore(db, "CREATE UNIQUE INDEX IF NOT EXISTS idx_app_users_uid ON app_users(uid)");
    db_exec_sql_ignore(db, "CREATE TABLE IF NOT EXISTS board_posts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), FOREIGN KEY(user_id) REFERENCES app_users(id) ON DELETE CASCADE)");
    db_exec_sql_ignore(db, "CREATE INDEX IF NOT EXISTS idx_board_posts_created_at ON board_posts(created_at DESC)");
    db_exec_sql_ignore(db, "CREATE TABLE IF NOT EXISTS board_post_likes (post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), PRIMARY KEY(post_id, user_id), FOREIGN KEY(post_id) REFERENCES board_posts(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES app_users(id) ON DELETE CASCADE)");
    db_exec_sql_ignore(db, "CREATE INDEX IF NOT EXISTS idx_board_post_likes_post_id ON board_post_likes(post_id)");
    db_exec_sql_ignore(db, "CREATE TABLE IF NOT EXISTS board_post_reactions (post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, emoji TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), PRIMARY KEY(post_id, user_id, emoji), FOREIGN KEY(post_id) REFERENCES board_posts(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES app_users(id) ON DELETE CASCADE)");
    db_exec_sql_ignore(db, "CREATE INDEX IF NOT EXISTS idx_board_post_reactions_post_id ON board_post_reactions(post_id)");
    db_exec_sql_ignore(db, "CREATE TABLE IF NOT EXISTS board_post_comments (id INTEGER PRIMARY KEY AUTOINCREMENT, post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, body TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), FOREIGN KEY(post_id) REFERENCES board_posts(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES app_users(id) ON DELETE CASCADE)");
    db_exec_sql_ignore(db, "CREATE INDEX IF NOT EXISTS idx_board_post_comments_post_id ON board_post_comments(post_id, created_at ASC)");
    db_exec_sql_ignore(db, "CREATE TABLE IF NOT EXISTS board_comment_reactions (comment_id INTEGER NOT NULL, user_id INTEGER NOT NULL, emoji TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), PRIMARY KEY(comment_id, user_id, emoji), FOREIGN KEY(comment_id) REFERENCES board_post_comments(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES app_users(id) ON DELETE CASCADE)");
    db_exec_sql_ignore(db, "CREATE INDEX IF NOT EXISTS idx_board_comment_reactions_comment_id ON board_comment_reactions(comment_id)");
    db_exec_sql_ignore(db, "CREATE TABLE IF NOT EXISTS board_post_reactions_v2 (post_id INTEGER NOT NULL, user_id INTEGER NOT NULL, emoji TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), PRIMARY KEY(post_id, user_id, emoji), FOREIGN KEY(post_id) REFERENCES board_posts(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES app_users(id) ON DELETE CASCADE)");
    db_exec_sql_ignore(db, "INSERT OR IGNORE INTO board_post_reactions_v2 (post_id,user_id,emoji,created_at,updated_at) SELECT post_id,user_id,emoji,created_at,updated_at FROM board_post_reactions");
    db_exec_sql_ignore(db, "DROP TABLE board_post_reactions");
    db_exec_sql_ignore(db, "ALTER TABLE board_post_reactions_v2 RENAME TO board_post_reactions");
    db_exec_sql_ignore(db, "CREATE INDEX IF NOT EXISTS idx_board_post_reactions_post_id ON board_post_reactions(post_id)");
    db_exec_sql_ignore(db, "CREATE TABLE IF NOT EXISTS board_comment_reactions_v2 (comment_id INTEGER NOT NULL, user_id INTEGER NOT NULL, emoji TEXT NOT NULL, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), updated_at INTEGER NOT NULL DEFAULT (strftime('%s','now')), PRIMARY KEY(comment_id, user_id, emoji), FOREIGN KEY(comment_id) REFERENCES board_post_comments(id) ON DELETE CASCADE, FOREIGN KEY(user_id) REFERENCES app_users(id) ON DELETE CASCADE)");
    db_exec_sql_ignore(db, "INSERT OR IGNORE INTO board_comment_reactions_v2 (comment_id,user_id,emoji,created_at,updated_at) SELECT comment_id,user_id,emoji,created_at,updated_at FROM board_comment_reactions");
    db_exec_sql_ignore(db, "DROP TABLE board_comment_reactions");
    db_exec_sql_ignore(db, "ALTER TABLE board_comment_reactions_v2 RENAME TO board_comment_reactions");
    db_exec_sql_ignore(db, "CREATE INDEX IF NOT EXISTS idx_board_comment_reactions_comment_id ON board_comment_reactions(comment_id)");
    db_exec_sql_ignore(db, "DELETE FROM board_post_reactions WHERE emoji='⁉'");
    db_exec_sql_ignore(db, "DELETE FROM board_comment_reactions WHERE emoji='⁉'");
    db_exec_sql_ignore(db, "CREATE TABLE IF NOT EXISTS pending_email_verifications (email TEXT PRIMARY KEY, username TEXT NOT NULL, password_hash TEXT NOT NULL, code_hash TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL DEFAULT (strftime('%s','now')))");
    db_exec_sql_ignore(db, "CREATE INDEX IF NOT EXISTS idx_pending_email_verifications_expires_at ON pending_email_verifications(expires_at)");

    sqlite3_stmt *stmt = NULL;
    if (db_prepare(db, &stmt, "SELECT id FROM app_users WHERE uid='' OR uid IS NULL")) {
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            int64_t id = sqlite3_column_int64(stmt, 0);
            char uidbuf[16] = {0};
            if (id == 1) {
                str_copy(uidbuf, sizeof(uidbuf), "01100001");
            } else if (!generate_unique_uid(db, uidbuf)) {
                sqlite3_finalize(stmt);
                return false;
            }
            sqlite3_stmt *up = NULL;
            if (db_prepare(db, &up, "UPDATE app_users SET uid=? WHERE id=?")) {
                db_bind_text(up, 1, uidbuf);
                db_bind_int64(up, 2, id);
                db_step_ok(db, up);
                sqlite3_finalize(up);
            }
        }
        sqlite3_finalize(stmt);
    }
    return true;
}
static sqlite3 *db_open(void) {
    sqlite3 *db = NULL; if (sqlite3_open(g_cfg.db_path, &db) != SQLITE_OK) { log_error("SQLite open failed: %s", db ? sqlite3_errmsg(db) : "unknown"); if (db) sqlite3_close(db); return NULL; }
    sqlite3_exec(db, "PRAGMA foreign_keys = ON;", NULL, NULL, NULL); sqlite3_busy_timeout(db, 3000); return db;
}
static bool db_exec_sql(sqlite3 *db, const char *sql) {
    char *errmsg = NULL; if (sqlite3_exec(db, sql, NULL, NULL, &errmsg) != SQLITE_OK) { log_error("SQLite exec failed: %s", errmsg ? errmsg : "unknown"); sqlite3_free(errmsg); return false; } return true;
}
static bool db_exec_file(sqlite3 *db, const char *path) {
    size_t len=0; char *sql = read_file_text(path, &len); if(!sql){ log_error("failed to read SQL file: %s", path); return false; } bool ok = db_exec_sql(db, sql); free(sql); return ok;
}
static bool db_prepare(sqlite3 *db, sqlite3_stmt **stmt, const char *sql) {
    if (sqlite3_prepare_v2(db, sql, -1, stmt, NULL) != SQLITE_OK) { log_error("SQLite prepare failed: %s", sqlite3_errmsg(db)); return false; } return true;
}
static void db_bind_text(sqlite3_stmt *stmt, int idx, const char *value) { sqlite3_bind_text(stmt, idx, value ? value : "", -1, SQLITE_TRANSIENT); }
static void db_bind_int64(sqlite3_stmt *stmt, int idx, int64_t v) { sqlite3_bind_int64(stmt, idx, v); }
static bool db_step_ok(sqlite3 *db, sqlite3_stmt *stmt) {
    int rc = sqlite3_step(stmt); if (rc != SQLITE_DONE && rc != SQLITE_ROW) { log_error("SQLite step failed: %s", sqlite3_errmsg(db)); sqlite3_finalize(stmt); return false; } return true;
}
static const char *content_type_for(const char *path) {
    const char *dot = strrchr(path, '.'); if (!dot) return "application/octet-stream";
    if (strcmp(dot, ".html") == 0) return "text/html; charset=utf-8";
    if (strcmp(dot, ".css") == 0) return "text/css; charset=utf-8";
    if (strcmp(dot, ".js") == 0) return "application/javascript; charset=utf-8";
    if (strcmp(dot, ".svg") == 0) return "image/svg+xml";
    if (strcmp(dot, ".png") == 0) return "image/png";
    if (strcmp(dot, ".jpg") == 0 || strcmp(dot, ".jpeg") == 0) return "image/jpeg";
    if (strcmp(dot, ".webp") == 0) return "image/webp";
    if (strcmp(dot, ".txt") == 0) return "text/plain; charset=utf-8";
    if (strcmp(dot, ".json") == 0) return "application/json; charset=utf-8";
    return "application/octet-stream";
}

static bool origin_in_csv(const char *origin, const char *csv) {
    if (!origin || !*origin) return true;
    if (!csv || !*csv) return false;
    char copy[1024];
    str_copy(copy, sizeof(copy), csv);
    char *save = NULL;
    for (char *tok = strtok_r(copy, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
        while (*tok && isspace((unsigned char)*tok)) ++tok;
        char *end = tok + strlen(tok);
        while (end > tok && isspace((unsigned char)end[-1])) --end;
        *end = '\0';
        if (*tok && strcmp(tok, origin) == 0) return true;
    }
    return false;
}
static const char *request_origin(struct MHD_Connection *connection) {
    return MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "Origin");
}
static bool allowed_origin_request(struct MHD_Connection *connection) {
    const char *origin = request_origin(connection);
    if (!origin || !*origin) return true;
    return origin_in_csv(origin, g_cfg.allowed_origins);
}
static enum MHD_Result add_cors_headers(struct MHD_Connection *connection, struct MHD_Response *response) {
    const char *origin = request_origin(connection);
    if (!origin || !*origin) return MHD_YES;
    if (!origin_in_csv(origin, g_cfg.allowed_origins)) return MHD_YES;
    enum MHD_Result ok = MHD_YES;
    ok &= MHD_add_response_header(response, "Access-Control-Allow-Origin", origin);
    ok &= MHD_add_response_header(response, "Access-Control-Allow-Credentials", "true");
    ok &= MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Accept");
    ok &= MHD_add_response_header(response, "Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    ok &= MHD_add_response_header(response, "Vary", "Origin");
    return ok;
}
static enum MHD_Result add_common_headers(struct MHD_Connection *connection, struct MHD_Response *response) {
    enum MHD_Result ok = MHD_YES;
    ok &= MHD_add_response_header(response, "X-Content-Type-Options", "nosniff");
    ok &= MHD_add_response_header(response, "Referrer-Policy", "strict-origin-when-cross-origin");
    ok &= MHD_add_response_header(response, "X-Frame-Options", "DENY");
    ok &= MHD_add_response_header(response, "Permissions-Policy", "camera=(), microphone=(), geolocation=()");
    ok &= MHD_add_response_header(response, "Cross-Origin-Opener-Policy", "same-origin");
    ok &= MHD_add_response_header(response, "Cross-Origin-Resource-Policy", "same-site");
    ok &= MHD_add_response_header(response, "Content-Security-Policy", "default-src 'self'; img-src 'self' data: https://avatars.githubusercontent.com https://github.com; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    ok &= add_cors_headers(connection, response);
    return ok;
}
static enum MHD_Result send_bytes(struct MHD_Connection *connection, unsigned int status, const void *data, size_t size, const char *content_type, const char *set_cookie) {
    struct MHD_Response *response = MHD_create_response_from_buffer(size, (void*)data, MHD_RESPMEM_MUST_COPY);
    if(!response) return MHD_NO;
    if(content_type) MHD_add_response_header(response, "Content-Type", content_type);
    add_common_headers(connection, response);
    if(set_cookie) MHD_add_response_header(response, "Set-Cookie", set_cookie);
    enum MHD_Result ret = MHD_queue_response(connection, status, response);
    MHD_destroy_response(response);
    return ret;
}
static enum MHD_Result send_text(struct MHD_Connection *connection, unsigned int status, const char *text, const char *content_type, const char *set_cookie) { return send_bytes(connection, status, text ? text : "", text ? strlen(text):0, content_type, set_cookie); }
static enum MHD_Result send_json(struct MHD_Connection *connection, unsigned int status, json_t *obj, const char *set_cookie) {
    char *dump = json_dumps(obj, JSON_COMPACT | JSON_ENSURE_ASCII); enum MHD_Result ret = send_text(connection, status, dump ? dump : "{}", "application/json; charset=utf-8", set_cookie); free(dump); return ret;
}
static enum MHD_Result send_error_json(struct MHD_Connection *connection, unsigned int status, const char *code, const char *message) {
    json_t *obj = json_object(); json_object_set_new(obj, "code", json_string(code ? code : "ERROR")); json_object_set_new(obj, "error", json_string(message ? message : "Request failed")); enum MHD_Result ret = send_json(connection, status, obj, NULL); json_decref(obj); return ret;
}
static void client_ip_key(struct MHD_Connection *connection, char *out, size_t out_cap) {
    if (!out || out_cap == 0) return;
    out[0] = '\0';
    const char *header = MHD_lookup_connection_value(connection, MHD_HEADER_KIND, "CF-Connecting-IP");
    if (header && *header) {
        size_t n = 0;
        while (header[n] && n + 1 < out_cap) {
            out[n] = header[n];
            ++n;
        }
        out[n] = '\0';
        while (*out && isspace((unsigned char)*out)) memmove(out, out + 1, strlen(out));
        char *end = out + strlen(out);
        while (end > out && isspace((unsigned char)end[-1])) *--end = '\0';
        if (*out) return;
    }

    const union MHD_ConnectionInfo *info = MHD_get_connection_info(connection, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
    if (info && info->client_addr) {
        const struct sockaddr *addr = info->client_addr;
        if (addr->sa_family == AF_INET) {
            const struct sockaddr_in *in = (const struct sockaddr_in *) addr;
            if (inet_ntop(AF_INET, &in->sin_addr, out, out_cap)) return;
        } else if (addr->sa_family == AF_INET6) {
            const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *) addr;
            if (inet_ntop(AF_INET6, &in6->sin6_addr, out, out_cap)) return;
        }
    }
    str_copy(out, out_cap, "unknown");
}
static bool rate_limit_allow(struct MHD_Connection *connection, const char *scope, unsigned int max_requests, unsigned int window_seconds) {
    char ip[96];
    char key[192];
    client_ip_key(connection, ip, sizeof(ip));
    snprintf(key, sizeof(key), "%s|%s", scope ? scope : "api", ip);

    time_t now = now_epoch();
    bool allowed = true;
    pthread_mutex_lock(&g_rate_limit_lock);
    int target = -1;
    int oldest = 0;
    for (int i = 0; i < RATE_LIMIT_BUCKETS; ++i) {
        if (g_rate_limits[i].key[0] && strcmp(g_rate_limits[i].key, key) == 0) {
            target = i;
            break;
        }
        if (!g_rate_limits[i].key[0] && target < 0) {
            target = i;
        }
        if (g_rate_limits[i].last_seen < g_rate_limits[oldest].last_seen) {
            oldest = i;
        }
    }
    if (target < 0) target = oldest;
    RateLimitBucket *bucket = &g_rate_limits[target];
    if (strcmp(bucket->key, key) != 0) {
        str_copy(bucket->key, sizeof(bucket->key), key);
        bucket->window_start = now;
        bucket->last_seen = now;
        bucket->count = 0;
    }
    if ((unsigned int)(now - bucket->window_start) >= window_seconds) {
        bucket->window_start = now;
        bucket->count = 0;
    }
    bucket->last_seen = now;
    if (bucket->count >= max_requests) {
        allowed = false;
    } else {
        bucket->count += 1;
    }
    pthread_mutex_unlock(&g_rate_limit_lock);
    return allowed;
}
static enum MHD_Result enforce_rate_limit(struct MHD_Connection *connection, const char *scope, unsigned int max_requests, unsigned int window_seconds) {
    if (rate_limit_allow(connection, scope, max_requests, window_seconds)) {
        return MHD_YES;
    }
    return send_error_json(connection, 429, "RATE_LIMITED", "Too many requests. Please try again later.");
}
static bool safe_path_join(char *out, size_t out_cap, const char *root, const char *url_path) {
    if (!out || out_cap == 0 || !root || !url_path || strstr(url_path, "..")) {
        return false;
    }
    const char *rel = url_path;
    if (*rel == '/') {
        ++rel;
    }
    if (*rel == '\0') {
        rel = "index.html";
    }
    int n = snprintf(out, out_cap, "%s/%s", root, rel);
    return n >= 0 && (size_t) n < out_cap;
}
static enum MHD_Result serve_static(struct MHD_Connection *connection, const char *url) {
    char path[PATH_MAX];
    if (strcmp(url, "/") == 0) url = "/index.html";
    if (strncmp(url, "/uploads/avatars/", 17) == 0) {
        const char *name = strrchr(url, '/');
        if (!name || !name[1]) return send_error_json(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND", "Not found");
        int n = snprintf(path, sizeof(path), "%s/%s", g_cfg.uploads_root, name + 1);
        if (n < 0 || (size_t)n >= sizeof(path)) return send_error_json(connection, MHD_HTTP_FORBIDDEN, "BAD_PATH", "Forbidden");
        return serve_binary_file(connection, path);
    }
    if (!safe_path_join(path, sizeof(path), g_cfg.web_root, url)) return send_error_json(connection, MHD_HTTP_FORBIDDEN, "BAD_PATH", "Forbidden");
    size_t len=0; char *data = read_file_text(path, &len); if(!data) return send_error_json(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND", "Not found"); enum MHD_Result ret = send_bytes(connection, MHD_HTTP_OK, data, len, content_type_for(path), NULL); free(data); return ret;
}
static enum MHD_Result serve_binary_file(struct MHD_Connection *connection, const char *path) {
    FILE *fp = fopen(path, "rb"); if(!fp) return send_error_json(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND", "Not found"); if(fseek(fp,0,SEEK_END)!=0){ fclose(fp); return send_error_json(connection,MHD_HTTP_INTERNAL_SERVER_ERROR,"IO_ERROR","Failed to read file"); } long sz=ftell(fp); rewind(fp); if(sz<0){ fclose(fp); return send_error_json(connection,MHD_HTTP_INTERNAL_SERVER_ERROR,"IO_ERROR","Failed to read file"); }
    unsigned char *buf = malloc((size_t)sz); if(!buf){ fclose(fp); return send_error_json(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "OOM", "Out of memory"); } size_t n=fread(buf,1,(size_t)sz,fp); fclose(fp); if(n!=(size_t)sz){ free(buf); return send_error_json(connection,MHD_HTTP_INTERNAL_SERVER_ERROR,"IO_ERROR","Failed to read file"); }
    enum MHD_Result ret = send_bytes(connection, MHD_HTTP_OK, buf, n, content_type_for(path), NULL); free(buf); return ret;
}
static const char *cookie_value(struct MHD_Connection *connection, const char *name) { return MHD_lookup_connection_value(connection, MHD_COOKIE_KIND, name); }

static char *http_only_cookie(const char *sid, bool delete_it) {
    char *buf = calloc(1024,1);
    if(!buf) return NULL;
    char domain_piece[320];
    if (g_cfg.cookie_domain[0]) {
        snprintf(domain_piece, sizeof(domain_piece), " Domain=%s;", g_cfg.cookie_domain);
    } else {
        domain_piece[0] = '\0';
    }
    if (delete_it) {
        snprintf(buf, 1024, "%s=; Path=/; HttpOnly; SameSite=Lax;%s%s Max-Age=0; Expires=Thu, 01 Jan 1970 00:00:00 GMT;",
                 COOKIE_NAME,
                 g_cfg.cookie_secure ? " Secure;" : "",
                 domain_piece);
    } else {
        snprintf(buf, 1024, "%s=%s; Path=/; HttpOnly; SameSite=Lax;%s%s Max-Age=2592000;",
                 COOKIE_NAME,
                 sid ? sid : "",
                 g_cfg.cookie_secure ? " Secure;" : "",
                 domain_piece);
    }
    return buf;
}
static json_t *contacts_json_for_user(sqlite3 *db, int64_t user_id) {
    json_t *arr = json_array(); sqlite3_stmt *stmt=NULL; if(!db_prepare(db,&stmt,"SELECT id,type,value,extra_label,position FROM app_contacts WHERE user_id=? ORDER BY position ASC, id ASC")) return arr; db_bind_int64(stmt,1,user_id); while(sqlite3_step(stmt) == SQLITE_ROW){ json_t *it=json_object(); json_object_set_new(it,"id",json_integer(sqlite3_column_int64(stmt,0))); json_object_set_new(it,"type",json_string((const char*)sqlite3_column_text(stmt,1))); json_object_set_new(it,"value",json_string((const char*)sqlite3_column_text(stmt,2))); json_object_set_new(it,"extraLabel",json_string((const char*)sqlite3_column_text(stmt,3))); json_array_append_new(arr,it);} sqlite3_finalize(stmt); return arr;
}
static json_t *repos_json_for_user(sqlite3 *db, int64_t user_id) {
    json_t *arr = json_array(); sqlite3_stmt *stmt=NULL; if(!db_prepare(db,&stmt,"SELECT id,display_name,repo_owner,repo_name,repo_full_name,repo_url,description_en,description_zh,position FROM app_repos WHERE user_id=? ORDER BY position ASC, id ASC")) return arr; db_bind_int64(stmt,1,user_id); while(sqlite3_step(stmt)==SQLITE_ROW){ json_t *it=json_object(); json_object_set_new(it,"id",json_integer(sqlite3_column_int64(stmt,0))); json_object_set_new(it,"name",json_string((const char*)sqlite3_column_text(stmt,1))); json_object_set_new(it,"owner",json_string((const char*)sqlite3_column_text(stmt,2))); json_object_set_new(it,"repo",json_string((const char*)sqlite3_column_text(stmt,3))); json_object_set_new(it,"fullName",json_string((const char*)sqlite3_column_text(stmt,4))); json_object_set_new(it,"url",json_string((const char*)sqlite3_column_text(stmt,5))); json_object_set_new(it,"descriptionEn",json_string((const char*)sqlite3_column_text(stmt,6))); json_object_set_new(it,"descriptionZh",json_string((const char*)sqlite3_column_text(stmt,7))); json_array_append_new(arr,it);} sqlite3_finalize(stmt); return arr;
}
static json_t *profile_json_for_user(sqlite3 *db, int64_t user_id, const char *lang, bool include_email, const char *role_override) {
    sqlite3_stmt *stmt=NULL; if(!db_prepare(db,&stmt,"SELECT uid,username,email,avatar_data_url,avatar_path,bio_intro_en,bio_intro_zh,account_desc_en,account_desc_zh,role,COALESCE(muted,0) FROM app_users WHERE id=?")) return NULL; db_bind_int64(stmt,1,user_id); if(sqlite3_step(stmt) != SQLITE_ROW){ sqlite3_finalize(stmt); return NULL; }
    const char *bio_en=(const char*)sqlite3_column_text(stmt,5); const char *bio_zh=(const char*)sqlite3_column_text(stmt,6); const char *desc_en=(const char*)sqlite3_column_text(stmt,7); const char *desc_zh=(const char*)sqlite3_column_text(stmt,8);
    const char *bio_line = (lang && strcmp(lang,"zh-CN")==0) ? (bio_zh && *bio_zh ? bio_zh : bio_en) : (bio_en && *bio_en ? bio_en : bio_zh);
    const char *desc_line = (lang && strcmp(lang,"zh-CN")==0) ? (desc_zh && *desc_zh ? desc_zh : desc_en) : (desc_en && *desc_en ? desc_en : desc_zh);
    const char *avatar_data = (const char*)sqlite3_column_text(stmt,3); const char *avatar_path = (const char*)sqlite3_column_text(stmt,4); const char *avatar_use = (avatar_path && *avatar_path) ? avatar_path : ((avatar_data && *avatar_data) ? avatar_data : "/assets/img/user.png");
    const char *uid_text=(const char*)sqlite3_column_text(stmt,0);
    json_t *obj=json_object(); json_object_set_new(obj,"id",json_integer(user_id)); json_object_set_new(obj,"uid",json_string(uid_text ? uid_text : "")); json_object_set_new(obj,"username",json_string((const char*)sqlite3_column_text(stmt,1))); if(include_email) json_object_set_new(obj,"email",json_string((const char*)sqlite3_column_text(stmt,2))); json_object_set_new(obj,"avatarDataUrl",json_string(avatar_use)); json_object_set_new(obj,"bioLine1",json_string(bio_line ? bio_line : "")); json_object_set_new(obj,"bioLine2",json_string(desc_line ? desc_line : "")); json_object_set_new(obj,"role",json_string(role_override ? role_override : (const char*)sqlite3_column_text(stmt,9))); if(include_email) json_object_set_new(obj,"muted",json_boolean(sqlite3_column_int(stmt,10) != 0));
    sqlite3_finalize(stmt);
    json_object_set_new(obj,"contacts",contacts_json_for_user(db,user_id)); json_object_set_new(obj,"repos",repos_json_for_user(db,user_id)); return obj;
}
static bool get_session_user(struct MHD_Connection *connection, SessionUser *out) {
    memset(out, 0, sizeof(*out)); const char *sid = cookie_value(connection, COOKIE_NAME); if(!sid || !*sid) return false; sqlite3 *db = db_open(); if(!db) return false;
    sqlite3_stmt *stmt=NULL; if(!db_prepare(db,&stmt,"SELECT u.id,COALESCE(u.uid,''),u.username,u.email,u.role,COALESCE(u.muted,0),COALESCE(u.avatar_data_url,''),COALESCE(u.avatar_path,'') FROM app_sessions s JOIN app_users u ON u.id=s.user_id WHERE s.session_id=? AND s.expires_at > ?")){ sqlite3_close(db); return false; }
    db_bind_text(stmt,1,sid); db_bind_int64(stmt,2, now_epoch()); bool ok = false; if(sqlite3_step(stmt)==SQLITE_ROW){ out->id = sqlite3_column_int64(stmt,0); str_copy(out->uid,sizeof(out->uid),(const char*)sqlite3_column_text(stmt,1)); str_copy(out->username,sizeof(out->username),(const char*)sqlite3_column_text(stmt,2)); str_copy(out->email,sizeof(out->email),(const char*)sqlite3_column_text(stmt,3)); str_copy(out->role,sizeof(out->role),(const char*)sqlite3_column_text(stmt,4)); out->muted = sqlite3_column_int(stmt,5) != 0; const char *a=(const char*)sqlite3_column_text(stmt,6); const char *p=(const char*)sqlite3_column_text(stmt,7); str_copy(out->avatar_data_url,sizeof(out->avatar_data_url),(p&&*p)?p:((a&&*a)?a:"/assets/img/default-avatar.svg")); ok = true; }
    sqlite3_finalize(stmt); sqlite3_close(db); return ok;
}
static size_t curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata) { Buffer *buf=(Buffer*)userdata; size_t total=size*nmemb; char *next=realloc(buf->data,buf->len+total+1); if(!next) return 0; buf->data=next; memcpy(buf->data+buf->len,ptr,total); buf->len += total; buf->data[buf->len]='\0'; return total; }
static size_t curl_read_cb(char *ptr, size_t size, size_t nmemb, void *userdata) {
    UploadBuffer *buf = (UploadBuffer *) userdata;
    size_t cap = size * nmemb;
    if (!buf || !buf->data || cap == 0 || buf->pos >= buf->len) {
        return 0;
    }
    size_t remaining = buf->len - buf->pos;
    size_t n = remaining < cap ? remaining : cap;
    memcpy(ptr, buf->data + buf->pos, n);
    buf->pos += n;
    return n;
}
static bool send_verification_email(const char *email, const char *code, char *err, size_t err_cap) {
    if (!g_cfg.smtp_url[0] || !g_cfg.smtp_from[0]) {
        str_copy(err, err_cap, "SMTP is not configured");
        return false;
    }
    CURL *curl = curl_easy_init();
    if (!curl) {
        str_copy(err, err_cap, "Failed to initialize mail client");
        return false;
    }

    char from_addr[320];
    char rcpt_addr[320];
    snprintf(from_addr, sizeof(from_addr), "<%s>", g_cfg.smtp_from);
    snprintf(rcpt_addr, sizeof(rcpt_addr), "<%s>", email ? email : "");

    char payload[2048];
    int n = snprintf(payload, sizeof(payload),
        "To: %s\r\n"
        "From: %s <%s>\r\n"
        "Subject: Your Warehouse-Blog verification code\r\n"
        "MIME-Version: 1.0\r\n"
        "Content-Type: text/plain; charset=UTF-8\r\n"
        "\r\n"
        "Your verification code is: %s\r\n"
        "\r\n"
        "This code expires in 10 minutes. If you did not request this registration, you can ignore this email.\r\n",
        email ? email : "",
        g_cfg.smtp_from_name[0] ? g_cfg.smtp_from_name : "Warehouse-Blog",
        g_cfg.smtp_from,
        code ? code : "");
    if (n < 0 || (size_t) n >= sizeof(payload)) {
        curl_easy_cleanup(curl);
        str_copy(err, err_cap, "Email payload is too large");
        return false;
    }

    UploadBuffer upload = { payload, strlen(payload), 0 };
    struct curl_slist *recipients = NULL;
    recipients = curl_slist_append(recipients, rcpt_addr);
    if (!recipients) {
        curl_easy_cleanup(curl);
        str_copy(err, err_cap, "Failed to prepare email recipient");
        return false;
    }

    curl_easy_setopt(curl, CURLOPT_URL, g_cfg.smtp_url);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, from_addr);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, curl_read_cb);
    curl_easy_setopt(curl, CURLOPT_READDATA, &upload);
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, strncasecmp(g_cfg.smtp_url, "smtps://", 8) == 0 ? (long) CURLUSESSL_ALL : (long) CURLUSESSL_NONE);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 15L);
    if (g_cfg.smtp_username[0]) curl_easy_setopt(curl, CURLOPT_USERNAME, g_cfg.smtp_username);
    if (g_cfg.smtp_password[0]) curl_easy_setopt(curl, CURLOPT_PASSWORD, g_cfg.smtp_password);

    CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        snprintf(err, err_cap, "Email send failed: %s", curl_easy_strerror(rc));
    }
    curl_slist_free_all(recipients);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK;
}
static json_t *github_fetch_repo(const char *repo_full, bool *exists_out) {
    *exists_out=false; CURL *curl = curl_easy_init(); if(!curl) return NULL; Buffer buf={0}; char url[512]; snprintf(url,sizeof(url),"https://api.github.com/repos/%s", repo_full); struct curl_slist *headers=NULL; headers = curl_slist_append(headers, "Accept: application/vnd.github+json"); headers = curl_slist_append(headers, "User-Agent: WarehouseBlog/1.0"); char auth[512]; if(g_cfg.github_token[0]){ snprintf(auth,sizeof(auth),"Authorization: Bearer %s", g_cfg.github_token); headers=curl_slist_append(headers,auth);} curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers); curl_easy_setopt(curl,CURLOPT_URL,url); curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,curl_write_cb); curl_easy_setopt(curl,CURLOPT_WRITEDATA,&buf); curl_easy_setopt(curl,CURLOPT_TIMEOUT,10L); CURLcode rc=curl_easy_perform(curl); long code=0; curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&code); curl_slist_free_all(headers); curl_easy_cleanup(curl); if(rc != CURLE_OK || code == 404 || code < 200 || code >= 300){ free(buf.data); return NULL; } json_error_t jerr; json_t *obj = json_loads(buf.data, 0, &jerr); free(buf.data); if(!obj) return NULL; *exists_out=true; return obj;
}
static bool valid_github_username(const char *username) {
    size_t len = username ? strlen(username) : 0;
    if (len == 0 || len > 39 || username[0] == '-' || username[len - 1] == '-') return false;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char) username[i];
        if (!isalnum(c) && c != '-') return false;
    }
    return true;
}
static bool github_username_from_contact(const char *value, char *out, size_t cap) {
    if (!value || !out || cap == 0) return false;
    char work[512]; str_copy(work, sizeof(work), value);
    char *trim = work; while (*trim && isspace((unsigned char)*trim)) ++trim;
    if (*trim == '@') ++trim;
    if (strncasecmp(trim, "https://", 8) == 0 || strncasecmp(trim, "http://", 7) == 0) {
        char *p = strstr(trim, "://"); trim = p ? p + 3 : trim;
    }
    if (strncasecmp(trim, "www.github.com/", 15) == 0) trim += 15;
    else if (strncasecmp(trim, "github.com/", 11) == 0) trim += 11;
    char *slash = strchr(trim, '/'); if (slash) *slash = '\0';
    char *q = strchr(trim, '?'); if (q) *q = '\0';
    char *hash = strchr(trim, '#'); if (hash) *hash = '\0';
    size_t len = strlen(trim); while (len > 0 && isspace((unsigned char)trim[len - 1])) trim[--len] = '\0';
    if (!valid_github_username(trim) || len >= cap) return false;
    str_copy(out, cap, trim);
    return true;
}
static json_t *github_scrape_user_repos(const char *username) {
    if (!valid_github_username(username)) return NULL;
    CURL *curl = curl_easy_init(); if(!curl) return NULL; Buffer buf={0}; char url[512]; snprintf(url,sizeof(url),"https://github.com/%s?tab=repositories", username);
    struct curl_slist *headers=NULL; headers = curl_slist_append(headers, "User-Agent: WarehouseBlog/1.0");
    curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers); curl_easy_setopt(curl,CURLOPT_URL,url); curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,curl_write_cb); curl_easy_setopt(curl,CURLOPT_WRITEDATA,&buf); curl_easy_setopt(curl,CURLOPT_TIMEOUT,10L); curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,1L);
    CURLcode rc=curl_easy_perform(curl); long code=0; curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&code); curl_slist_free_all(headers); curl_easy_cleanup(curl);
    if(rc != CURLE_OK || code < 200 || code >= 300 || !buf.data){ free(buf.data); return NULL; }
    json_t *arr = json_array(); char needle[160]; snprintf(needle,sizeof(needle),"href=\"/%s/", username); char *p = buf.data;
    while ((p = strstr(p, needle)) != NULL && json_array_size(arr) < 100) {
        p += strlen(needle);
        char *end = strchr(p, '"'); if (!end) break;
        size_t repo_len = (size_t)(end - p);
        if (repo_len > 0 && repo_len < 128 && !memchr(p, '/', repo_len)) {
            char repo[128] = {0}; memcpy(repo, p, repo_len); repo[repo_len] = '\0';
            char full[256]; snprintf(full,sizeof(full),"%s/%s", username, repo);
            bool duplicate = false; size_t idx; json_t *existing;
            json_array_foreach(arr, idx, existing) {
                const char *seen = json_string_value(json_object_get(existing, "full_name"));
                if (seen && strcmp(seen, full) == 0) { duplicate = true; break; }
            }
            if (!duplicate && valid_repo_name(full)) {
                char html_url[512]; snprintf(html_url,sizeof(html_url),"https://github.com/%s", full);
                json_t *obj = json_object();
                json_object_set_new(obj, "name", json_string(repo));
                json_object_set_new(obj, "full_name", json_string(full));
                json_object_set_new(obj, "html_url", json_string(html_url));
                json_t *owner = json_object(); json_object_set_new(owner, "login", json_string(username)); json_object_set_new(obj, "owner", owner);
                json_array_append_new(arr, obj);
            }
        }
    }
    free(buf.data);
    if (json_array_size(arr) == 0) { json_decref(arr); return NULL; }
    return arr;
}
static json_t *github_fetch_user_repos(const char *username) {
    if (!valid_github_username(username)) return NULL;
    CURL *curl = curl_easy_init(); if(!curl) return NULL; Buffer buf={0}; char url[512]; snprintf(url,sizeof(url),"https://api.github.com/users/%s/repos?type=public&sort=updated&per_page=100", username);
    struct curl_slist *headers=NULL; headers = curl_slist_append(headers, "Accept: application/vnd.github+json"); headers = curl_slist_append(headers, "User-Agent: WarehouseBlog/1.0"); char auth[512]; if(g_cfg.github_token[0]){ snprintf(auth,sizeof(auth),"Authorization: Bearer %s", g_cfg.github_token); headers=curl_slist_append(headers,auth);}
    curl_easy_setopt(curl,CURLOPT_HTTPHEADER,headers); curl_easy_setopt(curl,CURLOPT_URL,url); curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,curl_write_cb); curl_easy_setopt(curl,CURLOPT_WRITEDATA,&buf); curl_easy_setopt(curl,CURLOPT_TIMEOUT,10L);
    CURLcode rc=curl_easy_perform(curl); long code=0; curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&code); curl_slist_free_all(headers); curl_easy_cleanup(curl);
    if(rc != CURLE_OK || code < 200 || code >= 300){ free(buf.data); return github_scrape_user_repos(username); }
    json_error_t jerr; json_t *arr = json_loads(buf.data, 0, &jerr); free(buf.data); if(!json_is_array(arr)){ if(arr) json_decref(arr); return NULL; }
    return arr;
}
static int sync_github_public_repos(sqlite3 *db, int64_t user_id, const char *username) {
    if (!valid_github_username(username)) {
        return 0;
    }
    json_t *repos = github_fetch_user_repos(username); if(!repos) return 0;
    sqlite3_stmt *stmt = NULL; int inserted = 0; size_t idx; json_t *item;

    if (db_prepare(db, &stmt, "DELETE FROM app_repos WHERE user_id=?")) {
        db_bind_int64(stmt, 1, user_id);
        db_step_ok(db, stmt);
        sqlite3_finalize(stmt);
    }

    json_array_foreach(repos, idx, item) {
        const char *repo = json_string_value(json_object_get(item, "name"));
        const char *full = json_string_value(json_object_get(item, "full_name"));
        const char *url = json_string_value(json_object_get(item, "html_url"));
        const char *desc = json_string_value(json_object_get(item, "description"));
        json_t *owner_obj = json_object_get(item, "owner");
        const char *owner = json_string_value(json_object_get(owner_obj, "login"));
        if (!repo || !*repo || !full || !*full) continue;
        if (!owner || !*owner) owner = username;
        char fallback_url[512]; snprintf(fallback_url, sizeof(fallback_url), "https://github.com/%s", full);
        if (db_prepare(db, &stmt, "INSERT INTO app_repos (user_id,display_name,repo_owner,repo_name,repo_full_name,repo_url,description_en,description_zh,position) VALUES (?,?,?,?,?,?,?,?,?)")) {
            db_bind_int64(stmt, 1, user_id);
            db_bind_text(stmt, 2, repo);
            db_bind_text(stmt, 3, owner);
            db_bind_text(stmt, 4, repo);
            db_bind_text(stmt, 5, full);
            db_bind_text(stmt, 6, (url && *url) ? url : fallback_url);
            db_bind_text(stmt, 7, desc ? desc : "");
            db_bind_text(stmt, 8, desc ? desc : "");
            db_bind_int64(stmt, 9, (int64_t) idx);
            if (db_step_ok(db, stmt)) ++inserted;
            sqlite3_finalize(stmt);
        }
    }
    json_decref(repos);
    return inserted;
}
static json_t *stars_response(const char *repo_full) {
    sqlite3 *db = db_open(); if(!db) return NULL; sqlite3_stmt *stmt=NULL; time_t cutoff = now_epoch() - g_cfg.star_cache_seconds;
    if(db_prepare(db,&stmt,"SELECT stars, exists_flag, fetched_at FROM github_repo_cache WHERE repo_full_name=? AND fetched_at > ?")){ db_bind_text(stmt,1,repo_full); db_bind_int64(stmt,2,cutoff); if(sqlite3_step(stmt)==SQLITE_ROW){ json_t *obj=json_object(); json_object_set_new(obj,"repo",json_string(repo_full)); json_object_set_new(obj,"stars",json_integer(sqlite3_column_int(stmt,0))); json_object_set_new(obj,"exists",json_boolean(sqlite3_column_int(stmt,1)!=0)); char buf[64]; time_t ft = sqlite3_column_int64(stmt,2); struct tm tmv; gmtime_r(&ft,&tmv); strftime(buf,sizeof(buf),"%Y-%m-%dT%H:%M:%SZ",&tmv); json_object_set_new(obj,"fetchedAt",json_string(buf)); sqlite3_finalize(stmt); sqlite3_close(db); return obj; } sqlite3_finalize(stmt); }
    bool exists=false; json_t *gh = github_fetch_repo(repo_full,&exists); long stars=0; if(gh && exists){ json_t *count=json_object_get(gh,"stargazers_count"); stars=json_is_integer(count)?(long)json_integer_value(count):0; }
    if(db_prepare(db,&stmt,"INSERT INTO github_repo_cache (repo_full_name, stars, exists_flag, fetched_at) VALUES (?,?,?,?) ON CONFLICT(repo_full_name) DO UPDATE SET stars=excluded.stars, exists_flag=excluded.exists_flag, fetched_at=excluded.fetched_at")){ db_bind_text(stmt,1,repo_full); db_bind_int64(stmt,2,stars); db_bind_int64(stmt,3,exists?1:0); db_bind_int64(stmt,4,now_epoch()); db_step_ok(db,stmt); sqlite3_finalize(stmt);} sqlite3_close(db); if(gh) json_decref(gh);
    json_t *obj=json_object(); json_object_set_new(obj,"repo",json_string(repo_full)); json_object_set_new(obj,"stars",json_integer(stars)); json_object_set_new(obj,"exists",json_boolean(exists)); char nowbuf[64]; time_t now=now_epoch(); struct tm tmv; gmtime_r(&now,&tmv); strftime(nowbuf,sizeof(nowbuf),"%Y-%m-%dT%H:%M:%SZ",&tmv); json_object_set_new(obj,"fetchedAt",json_string(nowbuf)); return obj;
}
static void parent_dir_from_path(const char *path, char *out, size_t cap) {
    if (!out || cap == 0) {
        return;
    }
    str_copy(out, cap, path ? path : "");
    char *slash = strrchr(out, '/');
    if (!slash) {
        str_copy(out, cap, ".");
        return;
    }
    if (slash == out) {
        slash[1] = '\0';
        return;
    }
    *slash = '\0';
}
static bool remove_tree(const char *path) {
    if (!path || !*path) {
        return false;
    }
    struct stat st;
    if (lstat(path, &st) != 0) {
        return errno == ENOENT;
    }
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (!dir) {
            return false;
        }
        bool ok = true;
        struct dirent *ent;
        while ((ent = readdir(dir)) != NULL) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0) {
                continue;
            }
            char child[PATH_MAX];
            int n = snprintf(child, sizeof(child), "%s/%s", path, ent->d_name);
            if (n < 0 || (size_t) n >= sizeof(child)) {
                ok = false;
                continue;
            }
            if (!remove_tree(child)) {
                ok = false;
            }
        }
        closedir(dir);
        if (rmdir(path) != 0 && errno != ENOENT) {
            ok = false;
        }
        return ok;
    }
    return unlink(path) == 0 || errno == ENOENT;
}
static bool write_json_file_pretty(const char *path, json_t *obj) {
    char *dump = json_dumps(obj, JSON_INDENT(2) | JSON_PRESERVE_ORDER);
    if (!dump) {
        return false;
    }
    bool ok = write_text_file(path, dump);
    free(dump);
    return ok;
}
static bool export_state_json(void) {
    sqlite3 *db = db_open();
    if (!db) {
        return false;
    }

    char export_root[PATH_MAX] = {0};
    parent_dir_from_path(g_cfg.export_json_path, export_root, sizeof(export_root));
    if (!*export_root || strcmp(export_root, ".") == 0 || strcmp(export_root, "/") == 0) {
        sqlite3_close(db);
        return false;
    }

    remove_tree(export_root);
    mkdir_p(export_root);

    char users_dir[PATH_MAX] = {0};
    char posts_dir[PATH_MAX] = {0};
    if (snprintf(users_dir, sizeof(users_dir), "%s/users", export_root) < 0 ||
        snprintf(posts_dir, sizeof(posts_dir), "%s/posts", export_root) < 0) {
        sqlite3_close(db);
        return false;
    }
    mkdir_p(users_dir);
    mkdir_p(posts_dir);

    bool ok = true;
    json_t *root = json_object();
    json_t *users_index = json_array();
    json_t *posts_index = json_array();
    sqlite3_stmt *stmt = NULL;

    if (!db_prepare(db, &stmt,
        "SELECT id, uid, role, username, email, avatar_path, avatar_data_url, bio_intro_en, bio_intro_zh, account_desc_en, account_desc_zh, created_at "
        "FROM app_users ORDER BY CASE WHEN role='admin' THEN 0 ELSE 1 END, id ASC")) {
        ok = false;
    }

    while (ok && sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t user_id = sqlite3_column_int64(stmt, 0);
        const char *uid_text = (const char *) sqlite3_column_text(stmt, 1);
        const char *role = (const char *) sqlite3_column_text(stmt, 2);
        const char *username = (const char *) sqlite3_column_text(stmt, 3);
        const char *avatar_path = (const char *) sqlite3_column_text(stmt, 5);
        const char *avatar_data = (const char *) sqlite3_column_text(stmt, 6);
        const char *avatar_use = (avatar_path && *avatar_path) ? avatar_path : ((avatar_data && *avatar_data) ? avatar_data : "/assets/img/default-avatar.svg");
        const char *bio_en = (const char *) sqlite3_column_text(stmt, 7);
        const char *bio_zh = (const char *) sqlite3_column_text(stmt, 8);
        const char *desc_en = (const char *) sqlite3_column_text(stmt, 9);
        const char *desc_zh = (const char *) sqlite3_column_text(stmt, 10);
        int64_t created_at = sqlite3_column_int64(stmt, 11);

        char file_name[64] = {0};
        if (uid_text && *uid_text) {
            str_copy(file_name, sizeof(file_name), uid_text);
        } else {
            snprintf(file_name, sizeof(file_name), "user-%lld", (long long) user_id);
        }

        char rel_path[128] = {0};
        char abs_path[PATH_MAX] = {0};
        if (snprintf(rel_path, sizeof(rel_path), "users/%s.json", file_name) < 0 ||
            snprintf(abs_path, sizeof(abs_path), "%s/%s.json", users_dir, file_name) < 0) {
            ok = false;
            break;
        }

        json_t *user_obj = json_object();
        json_object_set_new(user_obj, "id", json_integer(user_id));
        json_object_set_new(user_obj, "uid", json_string(uid_text ? uid_text : ""));
        json_object_set_new(user_obj, "role", json_string(role ? role : "user"));
        json_object_set_new(user_obj, "username", json_string(username ? username : ""));
        json_object_set_new(user_obj, "avatarPath", json_string(avatar_use));
        json_object_set_new(user_obj, "avatarDataUrl", json_string(avatar_use));
        json_object_set_new(user_obj, "createdAt", json_integer(created_at));

        json_t *bio1 = json_object();
        json_object_set_new(bio1, "en", json_string(bio_en ? bio_en : ""));
        json_object_set_new(bio1, "zh-CN", json_string(bio_zh ? bio_zh : ""));
        json_object_set_new(user_obj, "bioLine1", bio1);

        json_t *bio2 = json_object();
        json_object_set_new(bio2, "en", json_string(desc_en ? desc_en : ""));
        json_object_set_new(bio2, "zh-CN", json_string(desc_zh ? desc_zh : ""));
        json_object_set_new(user_obj, "bioLine2", bio2);
        json_object_set_new(user_obj, "contacts", contacts_json_for_user(db, user_id));
        json_object_set_new(user_obj, "repos", repos_json_for_user(db, user_id));

        if (!write_json_file_pretty(abs_path, user_obj)) {
            ok = false;
        }
        json_decref(user_obj);
        if (!ok) {
            break;
        }

        json_t *summary = json_object();
        json_object_set_new(summary, "id", json_integer(user_id));
        json_object_set_new(summary, "uid", json_string(uid_text ? uid_text : ""));
        json_object_set_new(summary, "role", json_string(role ? role : "user"));
        json_object_set_new(summary, "username", json_string(username ? username : ""));
        json_object_set_new(summary, "file", json_string(rel_path));
        json_array_append_new(users_index, summary);
    }
    if (stmt) {
        sqlite3_finalize(stmt);
        stmt = NULL;
    }

    if (ok) {
        if (!db_prepare(db, &stmt,
            "SELECT p.id,p.body,p.created_at,u.id,u.uid,u.username,COALESCE(u.avatar_path,''),COALESCE(u.avatar_data_url,'') "
            "FROM board_posts p JOIN app_users u ON u.id=p.user_id ORDER BY p.created_at DESC, p.id DESC")) {
            ok = false;
        }
    }

    while (ok && sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t post_id = sqlite3_column_int64(stmt, 0);
        int64_t author_id = sqlite3_column_int64(stmt, 3);
        const char *author_uid = (const char *) sqlite3_column_text(stmt, 4);
        const char *author_name = (const char *) sqlite3_column_text(stmt, 5);
        const char *avatar_path = (const char *) sqlite3_column_text(stmt, 6);
        const char *avatar_data = (const char *) sqlite3_column_text(stmt, 7);
        const char *avatar_use = (avatar_path && *avatar_path) ? avatar_path : ((avatar_data && *avatar_data) ? avatar_data : "/assets/img/default-avatar.svg");
        int64_t created_at = sqlite3_column_int64(stmt, 2);

        char rel_post_path[128] = {0};
        char abs_post_path[PATH_MAX] = {0};
        char rel_comments_path[128] = {0};
        char abs_comments_path[PATH_MAX] = {0};
        if (snprintf(rel_post_path, sizeof(rel_post_path), "posts/post-%lld.json", (long long) post_id) < 0 ||
            snprintf(abs_post_path, sizeof(abs_post_path), "%s/post-%lld.json", posts_dir, (long long) post_id) < 0 ||
            snprintf(rel_comments_path, sizeof(rel_comments_path), "posts/post-%lld-comments.json", (long long) post_id) < 0 ||
            snprintf(abs_comments_path, sizeof(abs_comments_path), "%s/post-%lld-comments.json", posts_dir, (long long) post_id) < 0) {
            ok = false;
            break;
        }

        json_t *comments = comments_json_for_post(db, post_id, 0, false);
        size_t comment_count = json_array_size(comments);
        json_t *comments_doc = json_object();
        json_object_set_new(comments_doc, "postId", json_integer(post_id));
        json_object_set_new(comments_doc, "count", json_integer((json_int_t) comment_count));
        json_object_set_new(comments_doc, "comments", comments);
        if (!write_json_file_pretty(abs_comments_path, comments_doc)) {
            ok = false;
        }
        json_decref(comments_doc);
        if (!ok) {
            break;
        }

        json_t *post_obj = json_object();
        json_object_set_new(post_obj, "id", json_integer(post_id));
        json_object_set_new(post_obj, "body", json_string((const char *) sqlite3_column_text(stmt, 1)));
        json_object_set_new(post_obj, "createdAt", json_integer(created_at));
        json_t *author = json_object();
        json_object_set_new(author, "id", json_integer(author_id));
        json_object_set_new(author, "uid", json_string(author_uid ? author_uid : ""));
        json_object_set_new(author, "username", json_string(author_name ? author_name : ""));
        json_object_set_new(author, "avatarDataUrl", json_string(avatar_use));
        json_object_set_new(post_obj, "author", author);
        json_object_set_new(post_obj, "commentCount", json_integer((json_int_t) comment_count));
        json_object_set_new(post_obj, "reactions", reactions_json_for_target(db, "post", post_id, 0));
        json_object_set_new(post_obj, "commentsFile", json_string(rel_comments_path));
        if (!write_json_file_pretty(abs_post_path, post_obj)) {
            ok = false;
        }
        json_decref(post_obj);
        if (!ok) {
            break;
        }

        json_t *summary = json_object();
        json_object_set_new(summary, "id", json_integer(post_id));
        json_object_set_new(summary, "createdAt", json_integer(created_at));
        json_t *summary_author = json_object();
        json_object_set_new(summary_author, "id", json_integer(author_id));
        json_object_set_new(summary_author, "uid", json_string(author_uid ? author_uid : ""));
        json_object_set_new(summary_author, "username", json_string(author_name ? author_name : ""));
        json_object_set_new(summary, "author", summary_author);
        json_object_set_new(summary, "file", json_string(rel_post_path));
        json_object_set_new(summary, "commentsFile", json_string(rel_comments_path));
        json_array_append_new(posts_index, summary);
    }
    if (stmt) {
        sqlite3_finalize(stmt);
        stmt = NULL;
    }

    if (ok) {
        char users_index_path[PATH_MAX] = {0};
        char posts_index_path[PATH_MAX] = {0};
        if (snprintf(users_index_path, sizeof(users_index_path), "%s/index.json", users_dir) < 0 ||
            snprintf(posts_index_path, sizeof(posts_index_path), "%s/index.json", posts_dir) < 0) {
            ok = false;
        } else {
            json_t *users_doc = json_object();
            json_object_set_new(users_doc, "count", json_integer((json_int_t) json_array_size(users_index)));
            json_object_set_new(users_doc, "users", json_deep_copy(users_index));
            ok = write_json_file_pretty(users_index_path, users_doc);
            json_decref(users_doc);
            if (ok) {
                json_t *posts_doc = json_object();
                json_object_set_new(posts_doc, "count", json_integer((json_int_t) json_array_size(posts_index)));
                json_object_set_new(posts_doc, "posts", json_deep_copy(posts_index));
                ok = write_json_file_pretty(posts_index_path, posts_doc);
                json_decref(posts_doc);
            }
        }
    }

    if (ok) {
        json_object_set_new(root, "generatedAt", json_integer(now_epoch()));
        json_object_set_new(root, "usersIndex", json_string("users/index.json"));
        json_object_set_new(root, "postsIndex", json_string("posts/index.json"));
        json_object_set_new(root, "users", users_index);
        json_object_set_new(root, "posts", posts_index);
        users_index = NULL;
        posts_index = NULL;
        ok = write_json_file_pretty(g_cfg.export_json_path, root);
    }

    if (users_index) {
        json_decref(users_index);
    }
    if (posts_index) {
        json_decref(posts_index);
    }
    json_decref(root);
    sqlite3_close(db);
    return ok;
}
static bool save_avatar_data_url_to_disk(int64_t user_id, const char *data_url, char *public_path, size_t public_cap) {
    if (!data_url || strncmp(data_url, "data:image/", 11) != 0) {
        return false;
    }
    const char *semi = strchr(data_url, ';');
    const char *comma = strchr(data_url, ',');
    if (!semi || !comma || semi > comma) {
        return false;
    }
    if (strncmp(semi, ";base64", 7) != 0) {
        return false;
    }
    const char *mime = data_url + 5;
    size_t mime_len = (size_t) (semi - mime);
    char mimebuf[64] = {0};
    if (mime_len >= sizeof(mimebuf)) {
        return false;
    }
    memcpy(mimebuf, mime, mime_len);
    const char *ext = "bin";
    if (strcmp(mimebuf, "image/png") == 0) {
        ext = "png";
    } else if (strcmp(mimebuf, "image/jpeg") == 0) {
        ext = "jpg";
    } else if (strcmp(mimebuf, "image/webp") == 0) {
        ext = "webp";
    } else {
        return false;
    }
    const char *b64 = comma + 1;
    size_t b64len = strlen(b64);
    if (b64len > AVATAR_LIMIT) {
        return false;
    }
    size_t decoded_cap = ((b64len + 3) / 4) * 3 + 4;
    unsigned char *buf = malloc(decoded_cap);
    if (!buf) {
        return false;
    }
    int decoded = EVP_DecodeBlock(buf, (const unsigned char *) b64, (int) b64len);
    if (decoded < 0) {
        free(buf);
        return false;
    }
    while (b64len && b64[b64len - 1] == '=') {
        --decoded;
        --b64len;
    }
    time_t now = now_epoch();
    char path[PATH_MAX];
    int n = snprintf(path, sizeof(path), "%s/u%lld-%ld.%s", g_cfg.uploads_root, (long long) user_id, (long) now, ext);
    if (n < 0 || (size_t) n >= sizeof(path)) {
        free(buf);
        return false;
    }
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        free(buf);
        return false;
    }
    size_t wr = fwrite(buf, 1, (size_t) decoded, fp);
    fclose(fp);
    free(buf);
    if (wr != (size_t) decoded) {
        return false;
    }
    snprintf(public_path, public_cap, "/uploads/avatars/u%lld-%ld.%s", (long long) user_id, (long) now, ext);
    return true;
}
static json_t *json_body_parse(ConnectionInfo *ci) {
    json_error_t jerr; return json_loadb(ci && ci->body ? ci->body : "", ci ? ci->body_len : 0, 0, &jerr);
}
static int64_t ensure_admin_seed(void) {
    sqlite3 *db=db_open(); if(!db) die("failed to open SQLite during admin seed");
    sqlite3_stmt *stmt=NULL; int64_t admin_id=0; char *admin_email_norm = normalize_email(g_cfg.admin_email);
    if(db_prepare(db,&stmt,"SELECT id FROM app_users WHERE email=? LIMIT 1")){ db_bind_text(stmt,1,admin_email_norm); if(sqlite3_step(stmt)==SQLITE_ROW) admin_id = sqlite3_column_int64(stmt,0); sqlite3_finalize(stmt); }
    bool is_new = admin_id == 0;
    if(is_new){ char passhash[65]; if(!hash_sha256_hex(g_cfg.admin_password, passhash)) die("failed to hash admin password"); if(!db_prepare(db,&stmt,"INSERT INTO app_users (uid, role, username, email, password_hash, avatar_path, avatar_data_url) VALUES (?,?,?,?,?,?,?)")) die("failed to prepare admin insert"); db_bind_text(stmt,1,"01100001"); db_bind_text(stmt,2,"admin"); db_bind_text(stmt,3,g_cfg.admin_username); db_bind_text(stmt,4,admin_email_norm); db_bind_text(stmt,5,passhash); db_bind_text(stmt,6,"/assets/img/user.png"); db_bind_text(stmt,7,"./assets/img/user.png"); if(!db_step_ok(db,stmt)) die("failed to insert admin"); sqlite3_finalize(stmt); admin_id = sqlite3_last_insert_rowid(db); }
    if(!is_new){ if(db_prepare(db,&stmt,"UPDATE app_users SET role='admin' WHERE id=?")){ db_bind_int64(stmt,1,admin_id); db_step_ok(db,stmt); sqlite3_finalize(stmt); } free(admin_email_norm); sqlite3_close(db); export_state_json(); return admin_id; }
    free(admin_email_norm);
    json_error_t jerr; json_t *seed = json_load_file(g_cfg.admin_seed_path, 0, &jerr); if(seed){ json_t *profile=json_object_get(seed,"profile"); const char *bio_en=json_string_value(json_object_get(json_object_get(profile,"bioLine1"),"en")); const char *bio_zh=json_string_value(json_object_get(json_object_get(profile,"bioLine1"),"zh-CN")); const char *desc_en=json_string_value(json_object_get(json_object_get(profile,"bioLine2"),"en")); const char *desc_zh=json_string_value(json_object_get(json_object_get(profile,"bioLine2"),"zh-CN")); const char *avatar=json_string_value(json_object_get(profile,"avatarDataUrl"));
        if(db_prepare(db,&stmt,"UPDATE app_users SET uid=?, role='admin', username=?, email=?, avatar_path=?, avatar_data_url=?, bio_intro_en=?, bio_intro_zh=?, account_desc_en=?, account_desc_zh=? WHERE id=?")){ db_bind_text(stmt,1,"01100001"); db_bind_text(stmt,2,g_cfg.admin_username); db_bind_text(stmt,3,g_cfg.admin_email); db_bind_text(stmt,4,"/assets/img/user.png"); db_bind_text(stmt,5,avatar ? avatar : "./assets/img/user.png"); db_bind_text(stmt,6,bio_en?bio_en:""); db_bind_text(stmt,7,bio_zh?bio_zh:""); db_bind_text(stmt,8,desc_en?desc_en:""); db_bind_text(stmt,9,desc_zh?desc_zh:""); db_bind_int64(stmt,10,admin_id); db_step_ok(db,stmt); sqlite3_finalize(stmt); }
        db_exec_sql(db,"DELETE FROM app_contacts WHERE user_id IN (SELECT id FROM app_users WHERE role='admin')"); db_exec_sql(db,"DELETE FROM app_repos WHERE user_id IN (SELECT id FROM app_users WHERE role='admin')");
        json_t *contacts=json_object_get(profile,"contacts"); if(json_is_array(contacts)){ size_t idx; json_t *item; json_array_foreach(contacts, idx, item){ if(db_prepare(db,&stmt,"INSERT INTO app_contacts (user_id,type,value,extra_label,position) VALUES (?,?,?,?,?)")){ db_bind_int64(stmt,1,admin_id); db_bind_text(stmt,2,json_string_value(json_object_get(item,"type"))); db_bind_text(stmt,3,json_string_value(json_object_get(item,"value"))); db_bind_text(stmt,4,json_string_value(json_object_get(item,"extraLabel"))); db_bind_int64(stmt,5,(int64_t)idx); db_step_ok(db,stmt); sqlite3_finalize(stmt);} } }
        json_t *repos=json_object_get(profile,"repos"); if(json_is_array(repos)){ size_t idx; json_t *item; json_array_foreach(repos, idx, item){ if(db_prepare(db,&stmt,"INSERT INTO app_repos (user_id,display_name,repo_owner,repo_name,repo_full_name,repo_url,description_en,description_zh,position) VALUES (?,?,?,?,?,?,?,?,?)")){ db_bind_int64(stmt,1,admin_id); db_bind_text(stmt,2,json_string_value(json_object_get(item,"name"))); db_bind_text(stmt,3,json_string_value(json_object_get(item,"owner"))); db_bind_text(stmt,4,json_string_value(json_object_get(item,"repo"))); db_bind_text(stmt,5,json_string_value(json_object_get(item,"fullName"))); db_bind_text(stmt,6,json_string_value(json_object_get(item,"url"))); db_bind_text(stmt,7,json_string_value(json_object_get(item,"descriptionEn"))); db_bind_text(stmt,8,json_string_value(json_object_get(item,"descriptionZh"))); db_bind_int64(stmt,9,(int64_t)idx); db_step_ok(db,stmt); sqlite3_finalize(stmt);} } }
        json_decref(seed);
    }
    sqlite3_close(db); export_state_json(); return admin_id;
}
static enum MHD_Result handle_api_session(struct MHD_Connection *connection) {
    SessionUser su; if(!get_session_user(connection,&su)) return send_error_json(connection, MHD_HTTP_UNAUTHORIZED, "NOT_AUTHORIZED", "Not logged in"); json_t *obj=json_object(); json_t *u=json_object(); json_object_set_new(u,"id",json_integer(su.id)); json_object_set_new(u,"uid",json_string(su.uid)); json_object_set_new(u,"username",json_string(su.username)); json_object_set_new(u,"email",json_string(su.email)); json_object_set_new(u,"role",json_string(su.role)); json_object_set_new(u,"avatarDataUrl",json_string(su.avatar_data_url)); json_object_set_new(obj,"user",u); enum MHD_Result ret=send_json(connection,MHD_HTTP_OK,obj,NULL); json_decref(obj); return ret;
}
static int64_t admin_user_id(sqlite3 *db) {
    sqlite3_stmt *stmt=NULL; int64_t uid=0; if(db_prepare(db,&stmt,"SELECT id FROM app_users WHERE role='admin' ORDER BY id ASC LIMIT 1")){ if(sqlite3_step(stmt)==SQLITE_ROW) uid=sqlite3_column_int64(stmt,0); sqlite3_finalize(stmt);} return uid;
}
static const char *get_lang_param(struct MHD_Connection *connection) { const char *lang = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "lang"); return (lang && strcmp(lang,"zh-CN")==0) ? "zh-CN" : "en"; }
static enum MHD_Result handle_api_site_profile(struct MHD_Connection *connection) {
    sqlite3 *db=db_open(); if(!db) return send_error_json(connection,MHD_HTTP_INTERNAL_SERVER_ERROR,"DB_ERROR","Database unavailable"); int64_t uid=admin_user_id(db); json_t *profile = profile_json_for_user(db, uid, get_lang_param(connection), false, NULL); sqlite3_close(db); if(!profile) return send_error_json(connection,MHD_HTTP_NOT_FOUND,"NOT_FOUND","Profile not found"); json_t *obj=json_object(); json_object_set_new(obj,"profile",profile); enum MHD_Result ret=send_json(connection,MHD_HTTP_OK,obj,NULL); json_decref(obj); return ret;
}
static json_t *user_json_minimal(const SessionUser *su) {
    if (!su) {
        return json_null();
    }
    json_t *u = json_object();
    if (!u) {
        return json_null();
    }
    json_object_set_new(u, "id", json_integer(su->id));
    json_object_set_new(u, "uid", json_string(su->uid));
    json_object_set_new(u, "username", json_string(su->username));
    json_object_set_new(u, "email", json_string(su->email));
    json_object_set_new(u, "role", json_string(su->role));
    json_object_set_new(u, "muted", json_boolean(su->muted));
    json_object_set_new(u, "avatarDataUrl", json_string(su->avatar_data_url));
    return u;
}

static enum MHD_Result handle_api_me(struct MHD_Connection *connection) {
    SessionUser su;
    if (!get_session_user(connection, &su)) {
        return send_error_json(connection, MHD_HTTP_UNAUTHORIZED, "NOT_AUTHORIZED", "Not logged in");
    }

    sqlite3 *db = db_open();
    if (!db) {
        return send_error_json(connection, MHD_HTTP_INTERNAL_SERVER_ERROR, "DB_ERROR", "Database unavailable");
    }

    json_t *profile = profile_json_for_user(db, su.id, get_lang_param(connection), true, su.role);
    sqlite3_close(db);
    if (!profile) {
        return send_error_json(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND", "User not found");
    }

    json_t *obj = json_object();
    json_object_set_new(obj, "user", user_json_minimal(&su));
    json_object_set_new(obj, "profile", profile);
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, NULL);
    json_decref(obj);
    return ret;
}
static enum MHD_Result handle_api_login(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) {
        return send_error_json(connection, MHD_HTTP_FORBIDDEN, "BAD_ORIGIN", "Forbidden");
    }
    json_t *body = json_body_parse(ci);
    if (!body) {
        return send_error_json(connection, MHD_HTTP_BAD_REQUEST, "BAD_JSON", "Invalid JSON");
    }
    const char *email = json_string_value(json_object_get(body, "email"));
    const char *password = json_string_value(json_object_get(body, "password"));
    if (!valid_email(email)) {
        json_decref(body);
        return send_error_json(connection, 400, "BAD_EMAIL", "Invalid email");
    }
    if (!password || strlen(password) < 8 || strlen(password) > 128) {
        json_decref(body);
        return send_error_json(connection, 400, "BAD_PASSWORD", "Invalid password");
    }
    char *email_norm = normalize_email(email);
    char passhash[65];
    if (!email_norm || !hash_sha256_hex(password, passhash)) {
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "HASH_ERROR", "Hash failed");
    }
    sqlite3 *db = db_open();
    if (!db) {
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "DB_ERROR", "Database unavailable");
    }
    sqlite3_stmt *stmt = NULL;
    SessionUser su = {0};
    bool ok = false;
    if (db_prepare(db, &stmt, "SELECT id, COALESCE(uid,''), username, email, role, COALESCE(avatar_data_url,''), COALESCE(avatar_path,'') FROM app_users WHERE email=? AND password_hash=?")) {
        db_bind_text(stmt, 1, email_norm);
        db_bind_text(stmt, 2, passhash);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            su.id = sqlite3_column_int64(stmt, 0);
            str_copy(su.uid, sizeof(su.uid), (const char *) sqlite3_column_text(stmt, 1));
            str_copy(su.username, sizeof(su.username), (const char *) sqlite3_column_text(stmt, 2));
            str_copy(su.email, sizeof(su.email), (const char *) sqlite3_column_text(stmt, 3));
            str_copy(su.role, sizeof(su.role), (const char *) sqlite3_column_text(stmt, 4));
            const char *a = (const char *) sqlite3_column_text(stmt, 5);
            const char *p = (const char *) sqlite3_column_text(stmt, 6);
            str_copy(su.avatar_data_url, sizeof(su.avatar_data_url), (p && *p) ? p : ((a && *a) ? a : "/assets/img/default-avatar.svg"));
            ok = true;
        }
        sqlite3_finalize(stmt);
    }
    free(email_norm);
    json_decref(body);
    if (!ok) {
        sqlite3_close(db);
        return send_error_json(connection, 401, "INVALID_LOGIN", "The email address exists, but the password is incorrect!");
    }
    char *sid = generate_session_id();
    if (!sid) {
        sqlite3_close(db);
        return send_error_json(connection, 500, "SESSION_ERROR", "Failed to create session");
    }
    if (db_prepare(db, &stmt, "INSERT INTO app_sessions (session_id, user_id, expires_at) VALUES (?,?,?)")) {
        db_bind_text(stmt, 1, sid);
        db_bind_int64(stmt, 2, su.id);
        db_bind_int64(stmt, 3, now_epoch() + 30 * 24 * 3600);
        db_step_ok(db, stmt);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    char *cookie = http_only_cookie(sid, false);
    free(sid);
    json_t *obj = json_object();
    json_object_set_new(obj, "ok", json_true());
    json_object_set_new(obj, "user", user_json_minimal(&su));
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, cookie);
    free(cookie);
    json_decref(obj);
    return ret;
}

static enum MHD_Result handle_api_logout(struct MHD_Connection *connection) {
    if (!allowed_origin_request(connection)) {
        return send_error_json(connection, MHD_HTTP_FORBIDDEN, "BAD_ORIGIN", "Forbidden");
    }
    const char *sid = cookie_value(connection, COOKIE_NAME);
    if (sid && *sid) {
        sqlite3 *db = db_open();
        if (db) {
            sqlite3_stmt *stmt = NULL;
            if (db_prepare(db, &stmt, "DELETE FROM app_sessions WHERE session_id=?")) {
                db_bind_text(stmt, 1, sid);
                db_step_ok(db, stmt);
                sqlite3_finalize(stmt);
            }
            sqlite3_close(db);
        }
    }
    char *cookie = http_only_cookie("", true);
    json_t *obj = json_object();
    json_object_set_new(obj, "ok", json_true());
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, cookie);
    free(cookie);
    json_decref(obj);
    return ret;
}

static enum MHD_Result handle_api_register(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) {
        return send_error_json(connection, MHD_HTTP_FORBIDDEN, "BAD_ORIGIN", "Forbidden");
    }
    json_t *body = json_body_parse(ci);
    if (!body) {
        return send_error_json(connection, 400, "BAD_JSON", "Invalid JSON");
    }
    const char *username = json_string_value(json_object_get(body, "username"));
    const char *email = json_string_value(json_object_get(body, "email"));
    const char *password = json_string_value(json_object_get(body, "password"));
    const char *confirm_password = json_string_value(json_object_get(body, "confirmPassword"));
    if (!username || strlen(username) < 1 || strlen(username) > 30) {
        json_decref(body);
        return send_error_json(connection, 400, "BAD_USERNAME", "Invalid username");
    }
    if (!valid_email(email)) {
        json_decref(body);
        return send_error_json(connection, 400, "BAD_EMAIL", "Invalid email");
    }
    if (!password || strlen(password) < 8 || strlen(password) > 128) {
        json_decref(body);
        return send_error_json(connection, 400, "BAD_PASSWORD", "Invalid password");
    }
    if (!confirm_password || strcmp(password, confirm_password) != 0) {
        json_decref(body);
        return send_error_json(connection, 400, "PASSWORD_MISMATCH", "Passwords do not match");
    }
    char *email_norm = normalize_email(email);
    char passhash[65];
    if (!email_norm || !hash_sha256_hex(password, passhash)) {
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "HASH_ERROR", "Hash failed");
    }
    sqlite3 *db = db_open();
    if (!db) {
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "DB_ERROR", "Database unavailable");
    }
    sqlite3_stmt *stmt = NULL;
    bool exists = false;
    db_exec_sql_ignore(db, "DELETE FROM pending_email_verifications WHERE expires_at <= strftime('%s','now')");
    if (db_prepare(db, &stmt, "SELECT id FROM app_users WHERE email=? LIMIT 1")) {
        db_bind_text(stmt, 1, email_norm);
        exists = sqlite3_step(stmt) == SQLITE_ROW;
        sqlite3_finalize(stmt);
    }
    if (exists) {
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 409, "EMAIL_EXISTS", "This email address already exists!");
    }

    char code[7] = {0};
    char code_hash[65] = {0};
    if (!generate_verification_code(code) || !hash_sha256_hex(code, code_hash)) {
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "CODE_ERROR", "Failed to create verification code");
    }

    bool pending_ok = false;
    if (db_prepare(db, &stmt, "INSERT OR REPLACE INTO pending_email_verifications (email, username, password_hash, code_hash, attempts, expires_at, created_at) VALUES (?,?,?,?,0,?,?)")) {
        db_bind_text(stmt, 1, email_norm);
        db_bind_text(stmt, 2, username);
        db_bind_text(stmt, 3, passhash);
        db_bind_text(stmt, 4, code_hash);
        db_bind_int64(stmt, 5, now_epoch() + 10 * 60);
        db_bind_int64(stmt, 6, now_epoch());
        pending_ok = db_step_ok(db, stmt);
        if (pending_ok) sqlite3_finalize(stmt);
    }
    if (!pending_ok) {
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "DB_ERROR", "Database unavailable");
    }

    char mail_err[256] = {0};
    if (!send_verification_email(email_norm, code, mail_err, sizeof(mail_err))) {
        if (db_prepare(db, &stmt, "DELETE FROM pending_email_verifications WHERE email=?")) {
            db_bind_text(stmt, 1, email_norm);
            if (db_step_ok(db, stmt)) sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        log_error("%s", mail_err);
        return send_error_json(connection, 500, "MAIL_ERROR", mail_err[0] ? mail_err : "Failed to send verification email");
    }

    sqlite3_close(db);
    free(email_norm);
    json_decref(body);
    json_t *obj = json_object();
    json_object_set_new(obj, "ok", json_true());
    json_object_set_new(obj, "verificationRequired", json_true());
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, NULL);
    json_decref(obj);
    return ret;
}

static enum MHD_Result handle_api_verify_registration(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) {
        return send_error_json(connection, MHD_HTTP_FORBIDDEN, "BAD_ORIGIN", "Forbidden");
    }
    json_t *body = json_body_parse(ci);
    if (!body) {
        return send_error_json(connection, 400, "BAD_JSON", "Invalid JSON");
    }
    const char *email = json_string_value(json_object_get(body, "email"));
    const char *code = json_string_value(json_object_get(body, "code"));
    if (!valid_email(email)) {
        json_decref(body);
        return send_error_json(connection, 400, "BAD_EMAIL", "Invalid email");
    }
    if (!code || strlen(code) != 6) {
        json_decref(body);
        return send_error_json(connection, 400, "BAD_CODE", "Invalid verification code");
    }
    for (const char *p = code; *p; ++p) {
        if (!isdigit((unsigned char) *p)) {
            json_decref(body);
            return send_error_json(connection, 400, "BAD_CODE", "Invalid verification code");
        }
    }

    char *email_norm = normalize_email(email);
    char code_hash[65] = {0};
    if (!email_norm || !hash_sha256_hex(code, code_hash)) {
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "HASH_ERROR", "Hash failed");
    }

    sqlite3 *db = db_open();
    if (!db) {
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "DB_ERROR", "Database unavailable");
    }
    db_exec_sql_ignore(db, "DELETE FROM pending_email_verifications WHERE expires_at <= strftime('%s','now')");

    sqlite3_stmt *stmt = NULL;
    bool exists = false;
    if (db_prepare(db, &stmt, "SELECT id FROM app_users WHERE email=? LIMIT 1")) {
        db_bind_text(stmt, 1, email_norm);
        exists = sqlite3_step(stmt) == SQLITE_ROW;
        sqlite3_finalize(stmt);
    }
    if (exists) {
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 409, "EMAIL_EXISTS", "This email address already exists!");
    }

    char username[128] = {0};
    char passhash[65] = {0};
    char stored_code_hash[65] = {0};
    int attempts = 0;
    bool found = false;
    if (db_prepare(db, &stmt, "SELECT username, password_hash, code_hash, attempts FROM pending_email_verifications WHERE email=? AND expires_at>? LIMIT 1")) {
        db_bind_text(stmt, 1, email_norm);
        db_bind_int64(stmt, 2, now_epoch());
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            str_copy(username, sizeof(username), (const char *) sqlite3_column_text(stmt, 0));
            str_copy(passhash, sizeof(passhash), (const char *) sqlite3_column_text(stmt, 1));
            str_copy(stored_code_hash, sizeof(stored_code_hash), (const char *) sqlite3_column_text(stmt, 2));
            attempts = sqlite3_column_int(stmt, 3);
            found = true;
        }
        sqlite3_finalize(stmt);
    }
    if (!found) {
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 400, "CODE_EXPIRED", "Verification code has expired");
    }
    if (attempts >= 5) {
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 429, "TOO_MANY_ATTEMPTS", "Too many verification attempts");
    }
    if (strcmp(code_hash, stored_code_hash) != 0) {
        if (db_prepare(db, &stmt, "UPDATE pending_email_verifications SET attempts=attempts+1 WHERE email=?")) {
            db_bind_text(stmt, 1, email_norm);
            if (db_step_ok(db, stmt)) sqlite3_finalize(stmt);
        }
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 400, "BAD_CODE", "Invalid verification code");
    }

    char uidbuf[16] = {0};
    if (!generate_unique_uid(db, uidbuf)) {
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "UID_ERROR", "Failed to allocate UID");
    }
    bool user_created = false;
    const char *role = is_configured_admin_email(email_norm) ? "admin" : "user";
    if (db_prepare(db, &stmt, "INSERT INTO app_users (uid, role, username, email, password_hash, avatar_path, avatar_data_url) VALUES (?,?,?,?,?,?,?)")) {
        db_bind_text(stmt, 1, uidbuf);
        db_bind_text(stmt, 2, role);
        db_bind_text(stmt, 3, username);
        db_bind_text(stmt, 4, email_norm);
        db_bind_text(stmt, 5, passhash);
        db_bind_text(stmt, 6, "/assets/img/default-avatar.svg");
        db_bind_text(stmt, 7, "");
        user_created = db_step_ok(db, stmt);
        if (user_created) sqlite3_finalize(stmt);
    }
    int64_t user_id = sqlite3_last_insert_rowid(db);
    if (!user_created || user_id <= 0) {
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "DB_ERROR", "Failed to create account");
    }
    if (db_prepare(db, &stmt, "DELETE FROM pending_email_verifications WHERE email=?")) {
        db_bind_text(stmt, 1, email_norm);
        if (db_step_ok(db, stmt)) sqlite3_finalize(stmt);
    }
    char *sid = generate_session_id();
    if (!sid) {
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "SESSION_ERROR", "Failed to create session");
    }
    bool session_created = false;
    if (db_prepare(db, &stmt, "INSERT INTO app_sessions (session_id, user_id, expires_at) VALUES (?,?,?)")) {
        db_bind_text(stmt, 1, sid);
        db_bind_int64(stmt, 2, user_id);
        db_bind_int64(stmt, 3, now_epoch() + 30 * 24 * 3600);
        session_created = db_step_ok(db, stmt);
        if (session_created) sqlite3_finalize(stmt);
    }
    if (!session_created) {
        free(sid);
        sqlite3_close(db);
        free(email_norm);
        json_decref(body);
        return send_error_json(connection, 500, "SESSION_ERROR", "Failed to create session");
    }
    SessionUser su = {0};
    su.id = user_id;
    str_copy(su.uid, sizeof(su.uid), uidbuf);
    str_copy(su.username, sizeof(su.username), username);
    str_copy(su.email, sizeof(su.email), email_norm);
    str_copy(su.role, sizeof(su.role), role);
    str_copy(su.avatar_data_url, sizeof(su.avatar_data_url), "/assets/img/default-avatar.svg");
    sqlite3_close(db);
    free(email_norm);
    json_decref(body);
    export_state_json();
    char *cookie = http_only_cookie(sid, false);
    free(sid);
    json_t *obj = json_object();
    json_object_set_new(obj, "ok", json_true());
    json_object_set_new(obj, "user", user_json_minimal(&su));
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, cookie);
    free(cookie);
    json_decref(obj);
    return ret;
}

static enum MHD_Result handle_api_profile_save(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) {
        return send_error_json(connection, 403, "BAD_ORIGIN", "Forbidden");
    }
    SessionUser su;
    if (!get_session_user(connection, &su)) {
        return send_error_json(connection, 401, "NOT_AUTHORIZED", "Not logged in");
    }
    json_t *body = json_body_parse(ci);
    if (!body) {
        return send_error_json(connection, 400, "BAD_JSON", "Invalid JSON");
    }

    const char *bio1 = json_string_value(json_object_get(body, "bioLine1"));
    const char *bio2 = json_string_value(json_object_get(body, "bioLine2"));
    const char *bio1zh = json_string_value(json_object_get(body, "bioLine1Zh"));
    const char *bio2zh = json_string_value(json_object_get(body, "bioLine2Zh"));
    json_t *contacts = json_object_get(body, "contacts");
    json_t *repos = json_object_get(body, "repos");
    char github_username[64] = {0};
    int inserted_repos = 0;

    sqlite3 *db = db_open();
    if (!db) {
        json_decref(body);
        return send_error_json(connection, 500, "DB_ERROR", "Database unavailable");
    }
    sqlite3_stmt *stmt = NULL;
    if (db_prepare(db, &stmt, "UPDATE app_users SET bio_intro_en=?, bio_intro_zh=?, account_desc_en=?, account_desc_zh=? WHERE id=?")) {
        db_bind_text(stmt, 1, bio1 ? bio1 : "");
        db_bind_text(stmt, 2, bio1zh ? bio1zh : (bio1 ? bio1 : ""));
        db_bind_text(stmt, 3, bio2 ? bio2 : "");
        db_bind_text(stmt, 4, bio2zh ? bio2zh : (bio2 ? bio2 : ""));
        db_bind_int64(stmt, 5, su.id);
        db_step_ok(db, stmt);
        sqlite3_finalize(stmt);
    }
    if (db_prepare(db, &stmt, "DELETE FROM app_contacts WHERE user_id=?")) {
        db_bind_int64(stmt, 1, su.id);
        db_step_ok(db, stmt);
        sqlite3_finalize(stmt);
    }
    if (json_is_array(contacts)) {
        size_t idx;
        json_t *item;
        json_array_foreach(contacts, idx, item) {
            const char *type = json_string_value(json_object_get(item, "type"));
            const char *value = json_string_value(json_object_get(item, "value"));
            const char *extra = json_string_value(json_object_get(item, "extraLabel"));
            if (!value || !*value) {
                continue;
            }
            if (type && strcmp(type, "github") == 0 && !github_username[0]) {
                github_username_from_contact(value, github_username, sizeof(github_username));
            }
            if (db_prepare(db, &stmt, "INSERT INTO app_contacts (user_id,type,value,extra_label,position) VALUES (?,?,?,?,?)")) {
                db_bind_int64(stmt, 1, su.id);
                db_bind_text(stmt, 2, type ? type : "github");
                db_bind_text(stmt, 3, value);
                db_bind_text(stmt, 4, extra ? extra : "");
                db_bind_int64(stmt, 5, (int64_t) idx);
                db_step_ok(db, stmt);
                sqlite3_finalize(stmt);
            }
        }
    }
    if (db_prepare(db, &stmt, "DELETE FROM app_repos WHERE user_id=?")) {
        db_bind_int64(stmt, 1, su.id);
        db_step_ok(db, stmt);
        sqlite3_finalize(stmt);
    }
    if (json_is_array(repos)) {
        size_t idx;
        json_t *item;
        json_array_foreach(repos, idx, item) {
            const char *name = json_string_value(json_object_get(item, "name"));
            const char *repoInput = json_string_value(json_object_get(item, "repoInput"));
            if (!repoInput || !*repoInput) {
                repoInput = json_string_value(json_object_get(item, "fullName"));
            }
            if (!repoInput || !*repoInput) {
                repoInput = json_string_value(json_object_get(item, "url"));
            }
            const char *descEn = json_string_value(json_object_get(item, "descriptionEn"));
            const char *descZh = json_string_value(json_object_get(item, "descriptionZh"));
            char owner[128] = {0};
            char repo[128] = {0};
            char full[256] = {0};
            char url[512] = {0};
            if (!parse_repo_input(repoInput, owner, sizeof(owner), repo, sizeof(repo), full, sizeof(full), url, sizeof(url))) {
                continue;
            }
            if (db_prepare(db, &stmt, "INSERT INTO app_repos (user_id,display_name,repo_owner,repo_name,repo_full_name,repo_url,description_en,description_zh,position) VALUES (?,?,?,?,?,?,?,?,?)")) {
                db_bind_int64(stmt, 1, su.id);
                db_bind_text(stmt, 2, (name && *name) ? name : repo);
                db_bind_text(stmt, 3, owner);
                db_bind_text(stmt, 4, repo);
                db_bind_text(stmt, 5, full);
                db_bind_text(stmt, 6, url);
                db_bind_text(stmt, 7, descEn ? descEn : "");
                db_bind_text(stmt, 8, descZh ? descZh : "");
                db_bind_int64(stmt, 9, (int64_t) idx);
                if (db_step_ok(db, stmt)) {
                    ++inserted_repos;
                }
                sqlite3_finalize(stmt);
            }
        }
    }
    if (github_username[0]) {
        sync_github_public_repos(db, su.id, github_username);
    }
    sqlite3_close(db);
    export_state_json();
    json_decref(body);
    return handle_api_me(connection);
}
static enum MHD_Result handle_api_avatar(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) {
        return send_error_json(connection, 403, "BAD_ORIGIN", "Forbidden");
    }
    SessionUser su;
    if (!get_session_user(connection, &su)) {
        return send_error_json(connection, 401, "NOT_AUTHORIZED", "Not logged in");
    }
    json_t *body = json_body_parse(ci);
    if (!body) {
        return send_error_json(connection, 400, "BAD_JSON", "Invalid JSON");
    }
    const char *avatarDataUrl = json_string_value(json_object_get(body, "avatarDataUrl"));
    if (!avatarDataUrl || !*avatarDataUrl || strlen(avatarDataUrl) > AVATAR_LIMIT) {
        json_decref(body);
        return send_error_json(connection, 400, "BAD_IMAGE", "Invalid image");
    }
    char public_path[PATH_MAX] = "";
    save_avatar_data_url_to_disk(su.id, avatarDataUrl, public_path, sizeof(public_path));
    sqlite3 *db = db_open();
    if (!db) {
        json_decref(body);
        return send_error_json(connection, 500, "DB_ERROR", "Database unavailable");
    }
    sqlite3_stmt *stmt = NULL;
    if (db_prepare(db, &stmt, "UPDATE app_users SET avatar_path=?, avatar_data_url=? WHERE id=?")) {
        db_bind_text(stmt, 1, public_path);
        db_bind_text(stmt, 2, "");
        db_bind_int64(stmt, 3, su.id);
        db_step_ok(db, stmt);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    export_state_json();
    json_decref(body);
    return handle_api_me(connection);
}
static enum MHD_Result handle_api_cancel_self(struct MHD_Connection *connection) {
    if (!allowed_origin_request(connection)) {
        return send_error_json(connection, 403, "BAD_ORIGIN", "Forbidden");
    }
    SessionUser su;
    if (!get_session_user(connection, &su)) {
        return send_error_json(connection, 401, "NOT_AUTHORIZED", "Not logged in");
    }
    if (strcmp(su.role, "admin") == 0) {
        return send_error_json(connection, 403, "ADMIN_SELF_DELETE", "Admin cannot delete itself");
    }
    sqlite3 *db = db_open();
    if (!db) {
        return send_error_json(connection, 500, "DB_ERROR", "Database unavailable");
    }
    sqlite3_stmt *stmt = NULL;
    if (db_prepare(db, &stmt, "DELETE FROM app_users WHERE id=?")) {
        db_bind_int64(stmt, 1, su.id);
        db_step_ok(db, stmt);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    export_state_json();
    char *cookie = http_only_cookie("", true);
    json_t *obj = json_object();
    json_object_set_new(obj, "ok", json_true());
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, cookie);
    free(cookie);
    json_decref(obj);
    return ret;
}
static enum MHD_Result handle_api_admin_users(struct MHD_Connection *connection) {
    SessionUser su; if(!get_session_user(connection,&su)) return send_error_json(connection,401,"NOT_AUTHORIZED","Not logged in"); if(strcmp(su.role,"admin")!=0) return send_error_json(connection,403,"NOT_AUTHORIZED","Admin only"); sqlite3 *db=db_open(); if(!db) return send_error_json(connection,500,"DB_ERROR","Database unavailable"); sqlite3_stmt *stmt=NULL; json_t *arr=json_array(); if(db_prepare(db,&stmt,"SELECT id, username, email, role FROM app_users ORDER BY CASE WHEN role='admin' THEN 0 ELSE 1 END, id ASC")){ while(sqlite3_step(stmt)==SQLITE_ROW){ int64_t uid=sqlite3_column_int64(stmt,0); json_t *u=profile_json_for_user(db, uid, get_lang_param(connection), true, (const char*)sqlite3_column_text(stmt,3)); json_object_set_new(u,"isCurrentUser",json_boolean(uid==su.id)); json_array_append_new(arr,u);} sqlite3_finalize(stmt);} sqlite3_close(db); json_t *obj=json_object(); json_object_set_new(obj,"users",arr); enum MHD_Result ret=send_json(connection,MHD_HTTP_OK,obj,NULL); json_decref(obj); return ret;
}
static enum MHD_Result handle_api_admin_cancel_user(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) {
        return send_error_json(connection, 403, "BAD_ORIGIN", "Forbidden");
    }
    SessionUser su;
    if (!get_session_user(connection, &su)) {
        return send_error_json(connection, 401, "NOT_AUTHORIZED", "Not logged in");
    }
    if (strcmp(su.role, "admin") != 0) {
        return send_error_json(connection, 403, "NOT_AUTHORIZED", "Admin only");
    }
    json_t *body = json_body_parse(ci);
    if (!body) {
        return send_error_json(connection, 400, "BAD_JSON", "Invalid JSON");
    }
    const char *uid_text = json_string_value(json_object_get(body, "uid"));
    int64_t userId = json_integer_value(json_object_get(body, "userId"));
    sqlite3 *db = db_open();
    if (!db) {
        json_decref(body);
        return send_error_json(connection, 500, "DB_ERROR", "Database unavailable");
    }
    sqlite3_stmt *stmt = NULL;
    if (uid_text && *uid_text) {
        userId = user_id_by_uid(db, uid_text);
    }
    bool target_admin = false;
    if (!userId) {
        sqlite3_close(db);
        json_decref(body);
        return send_error_json(connection, 404, "NOT_FOUND", "User not found");
    }
    if (db_prepare(db, &stmt, "SELECT role FROM app_users WHERE id=?")) {
        db_bind_int64(stmt, 1, userId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *role = (const char *) sqlite3_column_text(stmt, 0);
            target_admin = role && strcmp(role, "admin") == 0;
        }
        sqlite3_finalize(stmt);
    }
    if (target_admin || userId == su.id) {
        sqlite3_close(db);
        json_decref(body);
        return send_error_json(connection, 403, "ADMIN_SELF_DELETE", "Admin cannot delete itself");
    }
    if (db_prepare(db, &stmt, "DELETE FROM app_users WHERE id=?")) {
        db_bind_int64(stmt, 1, userId);
        db_step_ok(db, stmt);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    export_state_json();
    json_decref(body);
    json_t *obj = json_object();
    json_object_set_new(obj, "ok", json_true());
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, NULL);
    json_decref(obj);
    return ret;
}
static enum MHD_Result handle_api_admin_grant_user(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) {
        return send_error_json(connection, 403, "BAD_ORIGIN", "Forbidden");
    }
    SessionUser su;
    if (!get_session_user(connection, &su)) {
        return send_error_json(connection, 401, "NOT_AUTHORIZED", "Not logged in");
    }
    if (strcmp(su.role, "admin") != 0) {
        return send_error_json(connection, 403, "NOT_AUTHORIZED", "Admin only");
    }
    json_t *body = json_body_parse(ci);
    if (!body) {
        return send_error_json(connection, 400, "BAD_JSON", "Invalid JSON");
    }
    const char *uid_text = json_string_value(json_object_get(body, "uid"));
    if (!uid_text || !*uid_text) {
        json_decref(body);
        return send_error_json(connection, 400, "BAD_UID", "Invalid UID");
    }
    sqlite3 *db = db_open();
    if (!db) {
        json_decref(body);
        return send_error_json(connection, 500, "DB_ERROR", "Database unavailable");
    }
    int64_t userId = user_id_by_uid(db, uid_text);
    if (!userId) {
        sqlite3_close(db);
        json_decref(body);
        return send_error_json(connection, 404, "NOT_FOUND", "User not found");
    }
    sqlite3_stmt *stmt = NULL;
    bool already_admin = false;
    if (db_prepare(db, &stmt, "SELECT role FROM app_users WHERE id=?")) {
        db_bind_int64(stmt, 1, userId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *role = (const char *) sqlite3_column_text(stmt, 0);
            already_admin = role && strcmp(role, "admin") == 0;
        }
        sqlite3_finalize(stmt);
    }
    if (!already_admin) {
        if (db_prepare(db, &stmt, "UPDATE app_users SET role='admin' WHERE id=?")) {
            db_bind_int64(stmt, 1, userId);
            db_step_ok(db, stmt);
            sqlite3_finalize(stmt);
        }
    }
    sqlite3_close(db);
    export_state_json();
    json_decref(body);
    json_t *obj = json_object();
    json_object_set_new(obj, "ok", json_true());
    json_object_set_new(obj, "alreadyAdmin", json_boolean(already_admin));
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, NULL);
    json_decref(obj);
    return ret;
}
static enum MHD_Result handle_api_admin_mute_user(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) {
        return send_error_json(connection, 403, "BAD_ORIGIN", "Forbidden");
    }
    SessionUser su;
    if (!get_session_user(connection, &su)) {
        return send_error_json(connection, 401, "NOT_AUTHORIZED", "Not logged in");
    }
    if (strcmp(su.role, "admin") != 0) {
        return send_error_json(connection, 403, "NOT_AUTHORIZED", "Admin only");
    }
    json_t *body = json_body_parse(ci);
    if (!body) {
        return send_error_json(connection, 400, "BAD_JSON", "Invalid JSON");
    }
    const char *uid_text = json_string_value(json_object_get(body, "uid"));
    bool muted = json_is_true(json_object_get(body, "muted"));
    if (!uid_text || !*uid_text) {
        json_decref(body);
        return send_error_json(connection, 400, "BAD_UID", "Invalid UID");
    }
    sqlite3 *db = db_open();
    if (!db) {
        json_decref(body);
        return send_error_json(connection, 500, "DB_ERROR", "Database unavailable");
    }
    int64_t userId = user_id_by_uid(db, uid_text);
    if (!userId) {
        sqlite3_close(db);
        json_decref(body);
        return send_error_json(connection, 404, "NOT_FOUND", "User not found");
    }
    if (userId == su.id) {
        sqlite3_close(db);
        json_decref(body);
        return send_error_json(connection, 403, "ADMIN_SELF_MUTE", "Admin cannot mute itself");
    }
    sqlite3_stmt *stmt = NULL;
    bool target_admin = false;
    if (db_prepare(db, &stmt, "SELECT role FROM app_users WHERE id=?")) {
        db_bind_int64(stmt, 1, userId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *role = (const char *) sqlite3_column_text(stmt, 0);
            target_admin = role && strcmp(role, "admin") == 0;
        }
        sqlite3_finalize(stmt);
    }
    if (target_admin) {
        sqlite3_close(db);
        json_decref(body);
        return send_error_json(connection, 403, "ADMIN_SELF_MUTE", "Cannot mute admin account");
    }
    if (db_prepare(db, &stmt, "UPDATE app_users SET muted=? WHERE id=?")) {
        db_bind_int64(stmt, 1, muted ? 1 : 0);
        db_bind_int64(stmt, 2, userId);
        db_step_ok(db, stmt);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    export_state_json();
    json_decref(body);
    json_t *obj = json_object();
    json_object_set_new(obj, "ok", json_true());
    json_object_set_new(obj, "muted", json_boolean(muted));
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, NULL);
    json_decref(obj);
    return ret;
}
static enum MHD_Result handle_api_admin_delete_repo(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) {
        return send_error_json(connection, 403, "BAD_ORIGIN", "Forbidden");
    }
    SessionUser su;
    if (!get_session_user(connection, &su)) {
        return send_error_json(connection, 401, "NOT_AUTHORIZED", "Not logged in");
    }
    if (strcmp(su.role, "admin") != 0) {
        return send_error_json(connection, 403, "NOT_AUTHORIZED", "Admin only");
    }
    json_t *body = json_body_parse(ci);
    if (!body) {
        return send_error_json(connection, 400, "BAD_JSON", "Invalid JSON");
    }
    int64_t repoId = json_integer_value(json_object_get(body, "repoId"));
    sqlite3 *db = db_open();
    if (!db) {
        json_decref(body);
        return send_error_json(connection, 500, "DB_ERROR", "Database unavailable");
    }
    sqlite3_stmt *stmt = NULL;
    bool own_admin_repo = false;
    if (db_prepare(db, &stmt, "SELECT u.role, u.id FROM app_repos r JOIN app_users u ON u.id=r.user_id WHERE r.id=?")) {
        db_bind_int64(stmt, 1, repoId);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            own_admin_repo = strcmp((const char *) sqlite3_column_text(stmt, 0), "admin") == 0 && sqlite3_column_int64(stmt, 1) == su.id;
        }
        sqlite3_finalize(stmt);
    }
    if (own_admin_repo) {
        sqlite3_close(db);
        json_decref(body);
        return send_error_json(connection, 403, "ADMIN_SELF_DELETE", "Admin cannot delete itself");
    }
    if (db_prepare(db, &stmt, "DELETE FROM app_repos WHERE id=?")) {
        db_bind_int64(stmt, 1, repoId);
        db_step_ok(db, stmt);
        sqlite3_finalize(stmt);
    }
    sqlite3_close(db);
    export_state_json();
    json_decref(body);
    json_t *obj = json_object();
    json_object_set_new(obj, "ok", json_true());
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, NULL);
    json_decref(obj);
    return ret;
}
static enum MHD_Result handle_api_stars(struct MHD_Connection *connection) {
    const char *repo = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "repo"); if(!valid_repo_name(repo)) return send_error_json(connection,400,"BAD_REPO","Invalid repo"); json_t *obj = stars_response(repo); if(!obj) return send_error_json(connection,502,"GITHUB_UPSTREAM","GitHub upstream failed"); enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, NULL); json_decref(obj); return ret;
}
static enum MHD_Result handle_api_health(struct MHD_Connection *connection) { json_t *obj=json_object(); json_object_set_new(obj,"ok",json_true()); json_object_set_new(obj,"storage",json_string("sqlite+json")); enum MHD_Result ret=send_json(connection,MHD_HTTP_OK,obj,NULL); json_decref(obj); return ret; }

typedef struct {
    const char *key;
    const char *emoji;
} ReactionOption;

static const ReactionOption *reaction_options(void) {
    static const ReactionOption allowed[] = {
        {"thumbs_up", "👍"},
        {"heart", "❤️"},
        {"laugh", "😂"},
        {"party", "🎉"},
        {"surprised", "😮"},
        {"sad", "😢"},
        {"question_white", "❔"},
        {"question_red", "❓"},
        {"rose", "🌹"},
        {"wilted_rose", "🥀"},
        {"thinking", "🤔"},
        {"mind_blown", "🤯"},
        {"skull", "💀"},
        {"crying", "😭"},
        {"check", "✅"},
        {"cross", "❌"},
        {NULL, NULL}
    };
    return allowed;
}

static const char *reaction_emoji_for_index(int64_t index) {
    const ReactionOption *allowed = reaction_options();
    if (index < 0) return NULL;
    for (int64_t i = 0; allowed[i].emoji; ++i) {
        if (i == index) return allowed[i].emoji;
    }
    return NULL;
}

static const char *reaction_emoji_for_key(const char *key) {
    if (!key || !*key) return NULL;
    const ReactionOption *allowed = reaction_options();
    for (int64_t i = 0; allowed[i].emoji; ++i) {
        if (strcmp(key, allowed[i].key) == 0) return allowed[i].emoji;
    }
    return NULL;
}

static bool valid_reaction_emoji(const char *emoji) {
    if (!emoji || !*emoji) return false;
    for (int64_t i = 0; ; ++i) {
        const char *allowed = reaction_emoji_for_index(i);
        if (!allowed) break;
        if (strcmp(emoji, allowed) == 0) return true;
    }
    return false;
}

static json_t *reactions_json_for_target(sqlite3 *db, const char *target_type, int64_t target_id, int64_t viewer_id) {
    json_t *arr = json_array();
    sqlite3_stmt *stmt = NULL;
    const bool is_comment = target_type && strcmp(target_type, "comment") == 0;
    const char *count_sql = is_comment
        ? "SELECT emoji, COUNT(*) FROM board_comment_reactions WHERE comment_id=? GROUP BY emoji ORDER BY COUNT(*) DESC, emoji ASC"
        : "SELECT emoji, COUNT(*) FROM board_post_reactions WHERE post_id=? GROUP BY emoji ORDER BY COUNT(*) DESC, emoji ASC";
    const char *viewer_sql = is_comment
        ? "SELECT 1 FROM board_comment_reactions WHERE comment_id=? AND user_id=? AND emoji=? LIMIT 1"
        : "SELECT 1 FROM board_post_reactions WHERE post_id=? AND user_id=? AND emoji=? LIMIT 1";
    if (!db_prepare(db, &stmt, count_sql)) {
        return arr;
    }
    db_bind_int64(stmt, 1, target_id);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *emoji = (const char *) sqlite3_column_text(stmt, 0);
        bool active = false;
        sqlite3_stmt *viewer_stmt = NULL;
        if (viewer_id > 0 && emoji && db_prepare(db, &viewer_stmt, viewer_sql)) {
            db_bind_int64(viewer_stmt, 1, target_id);
            db_bind_int64(viewer_stmt, 2, viewer_id);
            db_bind_text(viewer_stmt, 3, emoji);
            active = sqlite3_step(viewer_stmt) == SQLITE_ROW;
            sqlite3_finalize(viewer_stmt);
        }
        json_t *it = json_object();
        json_object_set_new(it, "emoji", json_string(emoji ? emoji : ""));
        json_object_set_new(it, "count", json_integer(sqlite3_column_int64(stmt, 1)));
        json_object_set_new(it, "active", json_boolean(active));
        json_array_append_new(arr, it);
    }
    sqlite3_finalize(stmt);
    return arr;
}

static json_t *comments_json_for_post(sqlite3 *db, int64_t post_id, int64_t viewer_id, bool viewer_is_admin) {
    json_t *arr = json_array();
    sqlite3_stmt *stmt = NULL;
    if (!db_prepare(db, &stmt, "SELECT c.id,c.body,c.created_at,u.id,u.uid,u.username,u.role,COALESCE(u.avatar_path,''),COALESCE(u.avatar_data_url,'') FROM board_post_comments c JOIN app_users u ON u.id=c.user_id WHERE c.post_id=? ORDER BY c.created_at ASC, c.id ASC")) {
        return arr;
    }
    db_bind_int64(stmt, 1, post_id);
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t author_id = sqlite3_column_int64(stmt, 3);
        const char *avatar_path = (const char *) sqlite3_column_text(stmt, 7);
        const char *avatar_data = (const char *) sqlite3_column_text(stmt, 8);
        const char *avatar_use = (avatar_path && *avatar_path) ? avatar_path : ((avatar_data && *avatar_data) ? avatar_data : "/assets/img/default-avatar.svg");
        json_t *it = json_object();
        json_object_set_new(it, "id", json_integer(sqlite3_column_int64(stmt, 0)));
        json_object_set_new(it, "body", json_string((const char *) sqlite3_column_text(stmt, 1)));
        json_object_set_new(it, "createdAt", json_integer(sqlite3_column_int64(stmt, 2)));
        json_t *author = json_object();
        json_object_set_new(author, "id", json_integer(author_id));
        json_object_set_new(author, "uid", json_string((const char *) sqlite3_column_text(stmt, 4)));
        json_object_set_new(author, "username", json_string((const char *) sqlite3_column_text(stmt, 5)));
        json_object_set_new(author, "role", json_string((const char *) sqlite3_column_text(stmt, 6)));
        json_object_set_new(author, "avatarDataUrl", json_string(avatar_use));
        json_object_set_new(it, "author", author);
        json_object_set_new(it, "canDelete", json_boolean(viewer_is_admin || (viewer_id > 0 && viewer_id == author_id)));
        json_object_set_new(it, "reactions", reactions_json_for_target(db, "comment", sqlite3_column_int64(stmt, 0), viewer_id));
        json_array_append_new(arr, it);
    }
    sqlite3_finalize(stmt);
    return arr;
}
static json_t *board_posts_json(sqlite3 *db, int64_t viewer_id, bool viewer_is_admin) {
    json_t *arr = json_array();
    sqlite3_stmt *stmt = NULL;
    if (!db_prepare(db, &stmt,
        "SELECT p.id,p.body,p.created_at,u.id,u.uid,u.username,u.role,COALESCE(u.avatar_path,''),COALESCE(u.avatar_data_url,'') "
        "FROM board_posts p JOIN app_users u ON u.id=p.user_id ORDER BY p.created_at DESC, p.id DESC LIMIT 200")) {
        return arr;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int64_t author_id = sqlite3_column_int64(stmt, 3);
        const char *avatar_path = (const char *) sqlite3_column_text(stmt, 7);
        const char *avatar_data = (const char *) sqlite3_column_text(stmt, 8);
        const char *avatar_use = (avatar_path && *avatar_path) ? avatar_path : ((avatar_data && *avatar_data) ? avatar_data : "/assets/img/default-avatar.svg");
        json_t *it = json_object();
        int64_t post_id = sqlite3_column_int64(stmt, 0);
        json_object_set_new(it, "id", json_integer(post_id));
        json_object_set_new(it, "body", json_string((const char *) sqlite3_column_text(stmt, 1)));
        json_object_set_new(it, "createdAt", json_integer(sqlite3_column_int64(stmt, 2)));
        json_t *author = json_object();
        json_object_set_new(author, "id", json_integer(author_id));
        json_object_set_new(author, "uid", json_string((const char *) sqlite3_column_text(stmt, 4)));
        json_object_set_new(author, "username", json_string((const char *) sqlite3_column_text(stmt, 5)));
        json_object_set_new(author, "role", json_string((const char *) sqlite3_column_text(stmt, 6)));
        json_object_set_new(author, "avatarDataUrl", json_string(avatar_use));
        json_object_set_new(it, "author", author);
        json_object_set_new(it, "canDelete", json_boolean(viewer_is_admin || (viewer_id > 0 && viewer_id == author_id)));
        json_t *comments = comments_json_for_post(db, post_id, viewer_id, viewer_is_admin);
        json_object_set_new(it, "commentCount", json_integer((json_int_t) json_array_size(comments)));
        json_object_set_new(it, "comments", comments);
        json_object_set_new(it, "reactions", reactions_json_for_target(db, "post", post_id, viewer_id));
        json_array_append_new(arr, it);
    }
    sqlite3_finalize(stmt);
    return arr;
}
static enum MHD_Result handle_api_user_by_uid(struct MHD_Connection *connection) {
    const char *uid = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "uid");
    if (!uid || !*uid || strlen(uid) > 8) {
        return send_error_json(connection, 400, "BAD_UID", "Invalid UID");
    }
    sqlite3 *db = db_open();
    if (!db) return send_error_json(connection,500,"DB_ERROR","Database unavailable");
    int64_t user_id = user_id_by_uid(db, uid);
    if (!user_id) {
        sqlite3_close(db);
        return send_error_json(connection,404,"NOT_FOUND","User not found");
    }
    SessionUser viewer = {0};
    bool viewer_is_admin = get_session_user(connection, &viewer) && strcmp(viewer.role, "admin") == 0;
    json_t *profile = profile_json_for_user(db, user_id, get_lang_param(connection), viewer_is_admin, NULL);
    sqlite3_close(db);
    if (!profile) return send_error_json(connection,404,"NOT_FOUND","User not found");
    json_t *obj = json_object();
    json_object_set_new(obj, "profile", profile);
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, NULL);
    json_decref(obj);
    return ret;
}
static enum MHD_Result handle_api_posts_list(struct MHD_Connection *connection) {
    SessionUser su = {0};
    bool logged_in = get_session_user(connection, &su);
    sqlite3 *db = db_open();
    if (!db) return send_error_json(connection,500,"DB_ERROR","Database unavailable");
    json_t *obj = json_object();
    json_object_set_new(obj, "posts", board_posts_json(db, logged_in ? su.id : 0, logged_in && strcmp(su.role, "admin") == 0));
    sqlite3_close(db);
    enum MHD_Result ret = send_json(connection, MHD_HTTP_OK, obj, NULL);
    json_decref(obj);
    return ret;
}
static enum MHD_Result handle_api_posts_create(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) return send_error_json(connection,403,"BAD_ORIGIN","Forbidden");
    SessionUser su = {0};
    if (!get_session_user(connection, &su)) return send_error_json(connection,401,"NOT_AUTHORIZED","Not logged in");
    if (su.muted) return send_error_json(connection,403,"USER_MUTED","You are muted");
    json_t *body = json_body_parse(ci);
    if (!body) return send_error_json(connection,400,"BAD_JSON","Invalid JSON");
    const char *post_body = json_string_value(json_object_get(body, "body"));
    if (!post_body || !*post_body || strlen(post_body) > POST_BODY_LIMIT) { json_decref(body); return send_error_json(connection,400,"BAD_POST","Invalid post body"); }
    sqlite3 *db = db_open();
    if (!db) { json_decref(body); return send_error_json(connection,500,"DB_ERROR","Database unavailable"); }
    sqlite3_stmt *stmt = NULL;
    if (db_prepare(db,&stmt,"INSERT INTO board_posts (user_id, body, created_at, updated_at) VALUES (?,?,?,?)")) {
        db_bind_int64(stmt,1,su.id); db_bind_text(stmt,2,post_body); db_bind_int64(stmt,3,now_epoch()); db_bind_int64(stmt,4,now_epoch()); db_step_ok(db,stmt); sqlite3_finalize(stmt);
    }
    sqlite3_close(db); json_decref(body); export_state_json();
    json_t *obj=json_object(); json_object_set_new(obj,"ok",json_true()); enum MHD_Result ret=send_json(connection,MHD_HTTP_OK,obj,NULL); json_decref(obj); return ret;
}
static enum MHD_Result handle_api_posts_reaction(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) return send_error_json(connection,403,"BAD_ORIGIN","Forbidden");
    SessionUser su = {0};
    if (!get_session_user(connection, &su)) return send_error_json(connection,401,"NOT_AUTHORIZED","Not logged in");
    json_t *body = json_body_parse(ci);
    if (!body) return send_error_json(connection,400,"BAD_JSON","Invalid JSON");
    const char *target_type = json_string_value(json_object_get(body, "targetType"));
    const char *emoji = json_string_value(json_object_get(body, "emoji"));
    const char *reaction_key = json_string_value(json_object_get(body, "reactionKey"));
    json_t *reaction_index_json = json_object_get(body, "reactionIndex");
    const char *canonical_emoji = reaction_emoji_for_key(reaction_key);
    if (!canonical_emoji && json_is_integer(reaction_index_json)) {
        canonical_emoji = reaction_emoji_for_index(json_integer_value(reaction_index_json));
    }
    if (!canonical_emoji && valid_reaction_emoji(emoji)) canonical_emoji = emoji;
    int64_t target_id = json_integer_value(json_object_get(body, "targetId"));
    bool is_comment = target_type && strcmp(target_type, "comment") == 0;
    bool is_post = target_type && strcmp(target_type, "post") == 0;
    if ((!is_post && !is_comment) || target_id <= 0 || !canonical_emoji) {
        json_decref(body);
        return send_error_json(connection,400,"BAD_REACTION","Invalid reaction");
    }
    sqlite3 *db = db_open();
    if (!db) { json_decref(body); return send_error_json(connection,500,"DB_ERROR","Database unavailable"); }
    sqlite3_stmt *stmt = NULL;
    int exists = 0;
    const char *exists_sql = is_comment ? "SELECT 1 FROM board_post_comments WHERE id=? LIMIT 1" : "SELECT 1 FROM board_posts WHERE id=? LIMIT 1";
    if (db_prepare(db, &stmt, exists_sql)) {
        db_bind_int64(stmt, 1, target_id);
        exists = sqlite3_step(stmt) == SQLITE_ROW;
        sqlite3_finalize(stmt);
        stmt = NULL;
    }
    if (!exists) {
        sqlite3_close(db);
        json_decref(body);
        return send_error_json(connection,404,"NOT_FOUND","Target not found");
    }

    const char *select_sql = is_comment
        ? "SELECT 1 FROM board_comment_reactions WHERE comment_id=? AND user_id=? AND emoji=? LIMIT 1"
        : "SELECT 1 FROM board_post_reactions WHERE post_id=? AND user_id=? AND emoji=? LIMIT 1";
    bool current_exists = false;
    if (db_prepare(db, &stmt, select_sql)) {
        db_bind_int64(stmt, 1, target_id);
        db_bind_int64(stmt, 2, su.id);
        db_bind_text(stmt, 3, canonical_emoji);
        current_exists = sqlite3_step(stmt) == SQLITE_ROW;
        sqlite3_finalize(stmt);
        stmt = NULL;
    }

    if (current_exists) {
        const char *delete_sql = is_comment
            ? "DELETE FROM board_comment_reactions WHERE comment_id=? AND user_id=? AND emoji=?"
            : "DELETE FROM board_post_reactions WHERE post_id=? AND user_id=? AND emoji=?";
        if (db_prepare(db, &stmt, delete_sql)) {
            db_bind_int64(stmt, 1, target_id);
            db_bind_int64(stmt, 2, su.id);
            db_bind_text(stmt, 3, canonical_emoji);
            db_step_ok(db, stmt);
            sqlite3_finalize(stmt);
        }
    } else {
        const char *insert_sql = is_comment
            ? "INSERT INTO board_comment_reactions (comment_id, user_id, emoji, created_at, updated_at) VALUES (?,?,?,?,?)"
            : "INSERT INTO board_post_reactions (post_id, user_id, emoji, created_at, updated_at) VALUES (?,?,?,?,?)";
        if (db_prepare(db, &stmt, insert_sql)) {
            int64_t now = now_epoch();
            db_bind_int64(stmt, 1, target_id);
            db_bind_int64(stmt, 2, su.id);
            db_bind_text(stmt, 3, canonical_emoji);
            db_bind_int64(stmt, 4, now);
            db_bind_int64(stmt, 5, now);
            db_step_ok(db, stmt);
            sqlite3_finalize(stmt);
        }
    }
    sqlite3_close(db);
    json_decref(body);
    export_state_json();
    json_t *obj=json_object(); json_object_set_new(obj,"ok",json_true()); enum MHD_Result ret=send_json(connection,MHD_HTTP_OK,obj,NULL); json_decref(obj); return ret;
}
static enum MHD_Result handle_api_posts_comment(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) return send_error_json(connection,403,"BAD_ORIGIN","Forbidden");
    SessionUser su = {0};
    if (!get_session_user(connection, &su)) return send_error_json(connection,401,"NOT_AUTHORIZED","Not logged in");
    if (su.muted) return send_error_json(connection,403,"USER_MUTED","You are muted");
    json_t *body = json_body_parse(ci);
    if (!body) return send_error_json(connection,400,"BAD_JSON","Invalid JSON");
    int64_t post_id = json_integer_value(json_object_get(body, "postId"));
    const char *comment = json_string_value(json_object_get(body, "body"));
    if (!comment || !*comment || strlen(comment) > COMMENT_BODY_LIMIT) { json_decref(body); return send_error_json(connection,400,"BAD_COMMENT","Invalid comment"); }
    sqlite3 *db = db_open();
    if (!db) { json_decref(body); return send_error_json(connection,500,"DB_ERROR","Database unavailable"); }
    sqlite3_stmt *stmt = NULL;
    if (db_prepare(db,&stmt,"INSERT INTO board_post_comments (post_id, user_id, body, created_at) VALUES (?,?,?,?)")) { db_bind_int64(stmt,1,post_id); db_bind_int64(stmt,2,su.id); db_bind_text(stmt,3,comment); db_bind_int64(stmt,4,now_epoch()); db_step_ok(db,stmt); sqlite3_finalize(stmt);}    
    sqlite3_close(db); json_decref(body); export_state_json();
    json_t *obj=json_object(); json_object_set_new(obj,"ok",json_true()); enum MHD_Result ret=send_json(connection,MHD_HTTP_OK,obj,NULL); json_decref(obj); return ret;
}
static enum MHD_Result handle_api_posts_comment_delete(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) return send_error_json(connection,403,"BAD_ORIGIN","Forbidden");
    SessionUser su = {0};
    if (!get_session_user(connection, &su)) return send_error_json(connection,401,"NOT_AUTHORIZED","Not logged in");
    json_t *body = json_body_parse(ci);
    if (!body) return send_error_json(connection,400,"BAD_JSON","Invalid JSON");
    int64_t comment_id = json_integer_value(json_object_get(body, "commentId"));
    if (comment_id <= 0) { json_decref(body); return send_error_json(connection,400,"BAD_COMMENT","Invalid comment"); }
    sqlite3 *db = db_open();
    if (!db) { json_decref(body); return send_error_json(connection,500,"DB_ERROR","Database unavailable"); }
    sqlite3_stmt *stmt = NULL;
    int64_t author_id = 0;
    if (db_prepare(db,&stmt,"SELECT user_id FROM board_post_comments WHERE id=?")) {
        db_bind_int64(stmt,1,comment_id);
        if (sqlite3_step(stmt)==SQLITE_ROW) author_id = sqlite3_column_int64(stmt,0);
        sqlite3_finalize(stmt);
    }
    if (!author_id) { sqlite3_close(db); json_decref(body); return send_error_json(connection,404,"NOT_FOUND","Comment not found"); }
    if (author_id != su.id && strcmp(su.role, "admin") != 0) { sqlite3_close(db); json_decref(body); return send_error_json(connection,403,"NOT_AUTHORIZED","Cannot delete this comment"); }
    if (db_prepare(db,&stmt,"DELETE FROM board_post_comments WHERE id=?")) { db_bind_int64(stmt,1,comment_id); db_step_ok(db,stmt); sqlite3_finalize(stmt); }
    sqlite3_close(db); json_decref(body); export_state_json();
    json_t *obj=json_object(); json_object_set_new(obj,"ok",json_true()); enum MHD_Result ret=send_json(connection,MHD_HTTP_OK,obj,NULL); json_decref(obj); return ret;
}
static enum MHD_Result handle_api_posts_delete(struct MHD_Connection *connection, ConnectionInfo *ci) {
    if (!allowed_origin_request(connection)) return send_error_json(connection,403,"BAD_ORIGIN","Forbidden");
    SessionUser su = {0};
    if (!get_session_user(connection, &su)) return send_error_json(connection,401,"NOT_AUTHORIZED","Not logged in");
    json_t *body = json_body_parse(ci);
    if (!body) return send_error_json(connection,400,"BAD_JSON","Invalid JSON");
    int64_t post_id = json_integer_value(json_object_get(body, "postId"));
    if (post_id <= 0) { json_decref(body); return send_error_json(connection,400,"BAD_POST","Invalid post"); }
    sqlite3 *db = db_open();
    if (!db) { json_decref(body); return send_error_json(connection,500,"DB_ERROR","Database unavailable"); }
    sqlite3_stmt *stmt = NULL;
    int64_t author_id = 0;
    if (db_prepare(db,&stmt,"SELECT user_id FROM board_posts WHERE id=?")) {
        db_bind_int64(stmt,1,post_id);
        if (sqlite3_step(stmt)==SQLITE_ROW) author_id = sqlite3_column_int64(stmt,0);
        sqlite3_finalize(stmt);
    }
    if (!author_id) { sqlite3_close(db); json_decref(body); return send_error_json(connection,404,"NOT_FOUND","Post not found"); }
    if (author_id != su.id && strcmp(su.role, "admin") != 0) { sqlite3_close(db); json_decref(body); return send_error_json(connection,403,"NOT_AUTHORIZED","Cannot delete this post"); }
    if (db_prepare(db,&stmt,"DELETE FROM board_posts WHERE id=?")) { db_bind_int64(stmt,1,post_id); db_step_ok(db,stmt); sqlite3_finalize(stmt); }
    sqlite3_close(db); json_decref(body); export_state_json();
    json_t *obj=json_object(); json_object_set_new(obj,"ok",json_true()); enum MHD_Result ret=send_json(connection,MHD_HTTP_OK,obj,NULL); json_decref(obj); return ret;
}
static enum MHD_Result handle_api_admin_delete_post(struct MHD_Connection *connection, ConnectionInfo *ci) {
    return handle_api_posts_delete(connection, ci);
}
static enum MHD_Result handle_api_options(struct MHD_Connection *connection) {
    return send_text(connection, MHD_HTTP_NO_CONTENT, "", "text/plain; charset=utf-8", NULL);
}
static enum MHD_Result route_request(struct MHD_Connection *connection, const char *url, const char *method, ConnectionInfo *ci) {
    if (strncmp(url, "/api/", 5) == 0) {
        if (strcmp(method, "OPTIONS") == 0) return handle_api_options(connection);
        if (strcmp(method, "GET") == 0 && strcmp(url, "/api/session") == 0) return handle_api_session(connection);
        if (strcmp(method, "GET") == 0 && strcmp(url, "/api/site-profile") == 0) return handle_api_site_profile(connection);
        if (strcmp(method, "GET") == 0 && strcmp(url, "/api/me") == 0) return handle_api_me(connection);
        if (strcmp(method, "GET") == 0 && strcmp(url, "/api/user-by-uid") == 0) return handle_api_user_by_uid(connection);
        if (strcmp(method, "GET") == 0 && strcmp(url, "/api/posts") == 0) return handle_api_posts_list(connection);
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/posts") == 0) {
            enum MHD_Result limited = enforce_rate_limit(connection, "post:create", 10, 300);
            if (limited != MHD_YES) return limited;
            return handle_api_posts_create(connection, ci);
        }
        if (strcmp(method, "DELETE") == 0 && strcmp(url, "/api/posts") == 0) return handle_api_posts_delete(connection, ci);
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/posts/reaction") == 0) {
            enum MHD_Result limited = enforce_rate_limit(connection, "post:reaction", 120, 60);
            if (limited != MHD_YES) return limited;
            return handle_api_posts_reaction(connection, ci);
        }
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/posts/comment") == 0) {
            enum MHD_Result limited = enforce_rate_limit(connection, "post:comment", 30, 300);
            if (limited != MHD_YES) return limited;
            return handle_api_posts_comment(connection, ci);
        }
        if (strcmp(method, "DELETE") == 0 && strcmp(url, "/api/posts/comment") == 0) return handle_api_posts_comment_delete(connection, ci);
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/auth/login") == 0) {
            enum MHD_Result limited = enforce_rate_limit(connection, "auth:login", 8, 300);
            if (limited != MHD_YES) return limited;
            return handle_api_login(connection, ci);
        }
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/auth/logout") == 0) return handle_api_logout(connection);
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/auth/register") == 0) {
            enum MHD_Result limited = enforce_rate_limit(connection, "auth:register", 3, 900);
            if (limited != MHD_YES) return limited;
            return handle_api_register(connection, ci);
        }
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/auth/verify-registration") == 0) {
            enum MHD_Result limited = enforce_rate_limit(connection, "auth:verify", 10, 600);
            if (limited != MHD_YES) return limited;
            return handle_api_verify_registration(connection, ci);
        }
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/profile") == 0) return handle_api_profile_save(connection, ci);
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/avatar") == 0) return handle_api_avatar(connection, ci);
        if (strcmp(method, "DELETE") == 0 && strcmp(url, "/api/auth/cancel-self") == 0) return handle_api_cancel_self(connection);
        if (strcmp(method, "GET") == 0 && strcmp(url, "/api/admin/users") == 0) return handle_api_admin_users(connection);
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/admin/cancel-user") == 0) return handle_api_admin_cancel_user(connection, ci);
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/admin/grant-user") == 0) return handle_api_admin_grant_user(connection, ci);
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/admin/mute-user") == 0) return handle_api_admin_mute_user(connection, ci);
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/admin/delete-repo") == 0) return handle_api_admin_delete_repo(connection, ci);
        if (strcmp(method, "POST") == 0 && strcmp(url, "/api/admin/delete-post") == 0) return handle_api_admin_delete_post(connection, ci);
        if (strcmp(method, "GET") == 0 && strcmp(url, "/api/stars") == 0) return handle_api_stars(connection);
        if (strcmp(method, "GET") == 0 && strcmp(url, "/api/health") == 0) return handle_api_health(connection);
        return send_error_json(connection, MHD_HTTP_NOT_FOUND, "NOT_FOUND", "Not found");
    }
    return serve_static(connection, url);
}
static enum MHD_Result access_handler(void *cls, struct MHD_Connection *connection, const char *url, const char *method, const char *version, const char *upload_data, size_t *upload_data_size, void **con_cls) {
    (void) cls;
    (void) version;
    ConnectionInfo *ci = *con_cls;
    if (!ci) {
        ci = calloc(1, sizeof(*ci));
        if (!ci) {
            return MHD_NO;
        }
        *con_cls = ci;
        return MHD_YES;
    }
    if (strcmp(method, "POST") == 0 || strcmp(method, "PUT") == 0 || strcmp(method, "PATCH") == 0 || strcmp(method, "DELETE") == 0) {
        if (*upload_data_size != 0) {
            if (ci->body_len + *upload_data_size > BODY_LIMIT) {
                return MHD_NO;
            }
            char *next = realloc(ci->body, ci->body_len + *upload_data_size + 1);
            if (!next) {
                return MHD_NO;
            }
            ci->body = next;
            memcpy(ci->body + ci->body_len, upload_data, *upload_data_size);
            ci->body_len += *upload_data_size;
            ci->body[ci->body_len] = '\0';
            *upload_data_size = 0;
            return MHD_YES;
        }
        if (ci->processed) {
            return MHD_YES;
        }
        ci->processed = 1;
        return route_request(connection, url, method, ci);
    }
    if (ci->processed) {
        return MHD_YES;
    }
    ci->processed = 1;
    return route_request(connection, url, method, ci);
}
static void request_completed(void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe) {
    (void) cls;
    (void) connection;
    (void) toe;

    ConnectionInfo *ci = *con_cls;
    if (ci) {
        free(ci->body);
        free(ci);
        *con_cls = NULL;
    }
}
int main(void) {
    load_config();
    mkdir_p(g_cfg.uploads_root);

    char export_dir[PATH_MAX];
    str_copy(export_dir, sizeof(export_dir), g_cfg.export_json_path);
    char *slash = strrchr(export_dir, '/');
    if (slash) {
        *slash = '\0';
        mkdir_p(export_dir);
    }

    char dbdir[PATH_MAX];
    str_copy(dbdir, sizeof(dbdir), g_cfg.db_path);
    slash = strrchr(dbdir, '/');
    if (slash) {
        *slash = '\0';
        mkdir_p(dbdir);
    }

    sqlite3 *db = db_open();
    if (!db) {
        die("failed to open SQLite database");
    }
    if (!db_exec_file(db, g_cfg.schema_path)) {
        sqlite3_close(db);
        die("failed to initialize schema");
    }
    if (!ensure_schema_migrations(db)) {
        sqlite3_close(db);
        die("failed to run schema migrations");
    }
    sqlite3_close(db);

    ensure_admin_seed();
    curl_global_init(CURL_GLOBAL_DEFAULT);

    unsigned int daemon_flags =
#ifdef MHD_USE_AUTO_INTERNAL_THREAD_COUNT
        MHD_USE_AUTO_INTERNAL_THREAD_COUNT;
#elif defined(MHD_USE_AUTO_INTERNAL_THREAD)
        MHD_USE_AUTO_INTERNAL_THREAD;
#else
        MHD_USE_INTERNAL_POLLING_THREAD;
#endif
    struct MHD_Daemon *daemon = MHD_start_daemon(
        daemon_flags,
        g_cfg.port,
        NULL,
        NULL,
        access_handler,
        NULL,
        MHD_OPTION_NOTIFY_COMPLETED,
        request_completed,
        MHD_OPTION_END
    );
    if (!daemon) {
        die("failed to start HTTP server on %s:%u", g_cfg.bind, (unsigned) g_cfg.port);
    }
    fprintf(stderr, "[warehouse-blog] listening on http://%s:%u\n", g_cfg.bind, (unsigned) g_cfg.port);
    for (;;) {
        pause();
    }
    MHD_stop_daemon(daemon);
    curl_global_cleanup();
    return 0;
}
