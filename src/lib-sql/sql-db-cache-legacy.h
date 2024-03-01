#ifndef SQL_DB_CACHE_LEGACY_H
#define SQL_DB_CACHE_LEGACY_H

struct sql_db_cache;

/* Like sql_init(), but use a connection pool. */
int sql_db_cache_new_legacy(struct sql_db_cache *cache,
			    const struct sql_legacy_settings *set,
			    struct sql_db **db_r, const char **error_r);

struct sql_db_cache *
sql_db_cache_init_legacy(unsigned int max_unused_connections);
void sql_db_cache_deinit_legacy(struct sql_db_cache **cache);

#endif
