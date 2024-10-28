#include <sqlite3.h>

sqlite3 *db;
int rc = sqlite3_open("totally_not_my_privateKeys.db", &db);
if (rc) {
    std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
    return 1;
}
const char *create_table_sql = R"(
    CREATE TABLE IF NOT EXISTS keys(
        kid INTEGER PRIMARY KEY AUTOINCREMENT,
        key BLOB NOT NULL,
        exp INTEGER NOT NULL
    );
)";
sqlite3_exec(db, create_table_sql, 0, 0, nullptr);

std::string priv_key = extract_priv_key(pkey); // Serialized in PEM format
int exp_time = static_cast<int>(std::chrono::system_clock::to_time_t(expiry_time));

const char *insert_sql = "INSERT INTO keys (key, exp) VALUES (?, ?)";
sqlite3_stmt *stmt;
sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
sqlite3_bind_text(stmt, 1, priv_key.c_str(), -1, SQLITE_STATIC);
sqlite3_bind_int(stmt, 2, exp_time);
sqlite3_step(stmt);
sqlite3_finalize(stmt);

bool expired = req.has_param("expired") && req.get_param_value("expired") == "true";
const char *select_sql = expired ? "SELECT key FROM keys WHERE exp <= ?" : "SELECT key FROM keys WHERE exp > ?";
int current_time = static_cast<int>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));

sqlite3_prepare_v2(db, select_sql, -1, &stmt, nullptr);
sqlite3_bind_int(stmt, 1, current_time);
if (sqlite3_step(stmt) == SQLITE_ROW) {
    std::string key(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
    // Deserialize `key` to use in signing the JWT...
}

const char *jwks_query = "SELECT key FROM keys WHERE exp > ?";
sqlite3_prepare_v2(db, jwks_query, -1, &stmt, nullptr);
sqlite3_bind_int(stmt, 1, current_time);
std::string jwks = R"({"keys": [)";
while (sqlite3_step(stmt) == SQLITE_ROW) {
    std::string key(reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0)));
    // Convert key to JSON structure here...
    jwks += formatted_key;
}
jwks += "]}}";
res.set_content(jwks, "application/json");
