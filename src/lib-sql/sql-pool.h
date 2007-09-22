#ifndef SQL_POOL_H
#define SQL_POOL_H

struct sql_pool;

/* Like sql_init(), but use a connection pool. */
struct sql_db *sql_pool_new(struct sql_pool *pool,
			    const char *db_driver, const char *connect_string);

struct sql_pool *sql_pool_init(unsigned int max_unused_connections);
void sql_pool_deinit(struct sql_pool **pool);

#endif
