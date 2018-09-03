#ifndef SQL_DB_CACHE_H
#define SQL_DB_CACHE_H

struct sql_db_cache;

/* Like sql_init(), but use a connection pool. */
struct sql_db *
sql_db_cache_new(struct sql_db_cache *cache,
		 const char *db_driver, const char *connect_string);
int sql_db_cache_new2(struct sql_db_cache *cache, const struct sql_settings *set,
		      struct sql_db **db_r, const char **error_r);

struct sql_db_cache *sql_db_cache_init(unsigned int max_unused_connections);
void sql_db_cache_deinit(struct sql_db_cache **cache);

#endif
