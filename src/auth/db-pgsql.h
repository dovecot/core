#ifndef __DB_PGSQL_H
#define __DB_PGSQL_H

#include <libpq-fe.h>

struct pgsql_connection;
struct pgsql_request;

typedef void pgqsl_query_callback_t(struct pgsql_connection *conn,
				    struct pgsql_request *request,
				    PGresult *res);

struct pgsql_settings {
	const char *connect;
	const char *password_query;
	const char *user_query;
	const char *allowed_chars;
	const char *default_pass_scheme;
};

struct pgsql_connection {
	struct pgsql_connection *next;

	pool_t pool;
	int refcount;

	char *config_path;
	struct pgsql_settings set;

	PGconn *pg;

	unsigned int connected:1;
};

struct pgsql_request {
	pgqsl_query_callback_t *callback;
	void *context;
};

int db_pgsql_is_valid_username(struct pgsql_connection *conn,
			       const char *username);

void db_pgsql_query(struct pgsql_connection *conn, const char *query,
		    struct pgsql_request *request);

struct pgsql_connection *db_pgsql_init(const char *config_path);
void db_pgsql_unref(struct pgsql_connection *conn);

#endif
