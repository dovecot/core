#ifndef __DB_MYSQL_H
#define __DB_MYSQL_H

#include <mysql.h>
#include <errmsg.h>

struct mysql_connection;
struct mysql_request;

typedef void mysql_query_callback_t(struct mysql_connection *conn,
				    struct mysql_request *request,
				    MYSQL_RES *res);

struct mysql_settings {
	const char *db_host;
	unsigned int db_port;
	const char *db_unix_socket;
	const char *db;
	const char *db_user;
	const char *db_passwd;
	unsigned int db_client_flags;
	const char *ssl_key;
	const char *ssl_cert;
	const char *ssl_ca;
	const char *ssl_ca_path;
	const char *ssl_cipher;
	const char *password_query;
	const char *user_query;
	const char *default_pass_scheme;
};

struct mysql_connection {
	struct mysql_connection *next;

	pool_t pool;
	int refcount;

	char *config_path;
	struct mysql_settings set;

	MYSQL *mysql;

	unsigned int connected:1;
};

struct mysql_request {
	mysql_query_callback_t *callback;
	void *context;
};

void db_mysql_query(struct mysql_connection *conn, const char *query,
		    struct mysql_request *request);

struct mysql_connection *db_mysql_init(const char *config_path);
void db_mysql_unref(struct mysql_connection *conn);

#endif
