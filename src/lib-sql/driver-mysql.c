/* Copyright (C) 2003-2004 Timo Sirainen, Alex Howansky */

#include "lib.h"
#include "sql-api-private.h"

#ifdef HAVE_MYSQL
#include <stdlib.h>
#include <time.h>
#include <mysql.h>
#include <errmsg.h>

struct mysql_db {
	struct sql_db api;

	pool_t pool;
	const char *host, *user, *password, *dbname, *unix_socket;
	const char *ssl_cert, *ssl_key, *ssl_ca, *ssl_ca_path, *ssl_cipher;
	unsigned int port, client_flags;
	MYSQL *mysql;

	time_t last_connect;

	unsigned int connected:1;
	unsigned int ssl:1;
};

struct mysql_result {
	struct sql_result api;
	MYSQL_RES *result;
        MYSQL_ROW row;

	MYSQL_FIELD *fields;
	unsigned int fields_count;
};

extern struct sql_result driver_mysql_result;
extern struct sql_result driver_mysql_error_result;

static int driver_mysql_connect(struct mysql_db *db)
{
	const char *unix_socket, *host;
	time_t now;

	if (db->connected)
		return TRUE;

	/* don't try reconnecting more than once a second */
	now = time(NULL);
	if (db->last_connect == now)
		return FALSE;
	db->last_connect = now;

	if (*db->host == '/') {
		unix_socket = db->host;
		host = NULL;
	} else {
		unix_socket = NULL;
		host = db->host;
	}

	if (mysql_real_connect(db->mysql, host, db->user, db->password,
			       db->dbname, db->port, unix_socket,
			       db->client_flags) == NULL) {
		i_error("mysql: Connect failed to %s: %s",
			db->dbname, mysql_error(db->mysql));
		return FALSE;
	} else {
		i_info("mysql: Connected to %s%s", db->dbname,
		       db->ssl ? " using SSL" : "");
		db->connected = TRUE;
		return TRUE;
	}
}

static void driver_mysql_parse_connect_string(struct mysql_db *db,
					      const char *connect_string)
{
	const char *const *args, *name, *value;
	const char **field;

	db->ssl_cipher = "HIGH";

	t_push();
	args = t_strsplit_spaces(connect_string, " ");
	for (; *args != NULL; args++) {
		value = strchr(*args, '=');
		if (value == NULL) {
			i_fatal("mysql: Missing value in connect string: %s",
				*args);
		}
		name = t_strdup_until(*args, value);
		value++;

		field = NULL;
		if (strcmp(name, "host") == 0 || strcmp(name, "hostaddr") == 0)
			field = &db->host;
		else if (strcmp(name, "user") == 0)
			field = &db->user;
		else if (strcmp(name, "password") == 0)
			field = &db->password;
		else if (strcmp(name, "dbname") == 0)
			field = &db->dbname;
		else if (strcmp(name, "port") == 0)
			db->port = atoi(value);
		else if (strcmp(name, "client_flags") == 0)
			db->client_flags = atoi(value);
		else if (strcmp(name, "ssl_cert") == 0)
			field = &db->ssl_cert;
		else if (strcmp(name, "ssl_key") == 0)
			field = &db->ssl_key;
		else if (strcmp(name, "ssl_ca") == 0)
			field = &db->ssl_ca;
		else if (strcmp(name, "ssl_ca_path") == 0)
			field = &db->ssl_ca_path;
		else if (strcmp(name, "ssl_cipher") == 0)
			field = &db->ssl_cipher;
		else
			i_fatal("mysql: Unknown connect string: %s", name);

		if (field != NULL)
			*field = p_strdup(db->pool, value);
	}
	t_pop();
}

static struct sql_db *driver_mysql_init(const char *connect_string)
{
	struct mysql_db *db;
	pool_t pool;

	pool = pool_alloconly_create("mysql driver", 256);

	db = p_new(pool, struct mysql_db, 1);
	db->pool = pool;
	db->api = driver_mysql_db;
	db->mysql = mysql_init(NULL);
	if (db->mysql == NULL)
		i_fatal("mysql_init() failed");

	driver_mysql_parse_connect_string(db, connect_string);
	if (db->ssl_ca != NULL || db->ssl_ca_path != NULL) {
#ifdef HAVE_MYSQL_SSL
		mysql_ssl_set(db->mysql, db->ssl_key, db->ssl_cert,
			      db->ssl_ca, db->ssl_ca_path
#ifdef HAVE_MYSQL_SSL_CIPHER
			      , db->ssl_cipher
#endif
			     );
		db->ssl = TRUE;
#else
		i_fatal("mysql: SSL support not compiled in "
			"(remove ssl_ca and ssl_ca_path settings)");
#endif
	}
	(void)driver_mysql_connect(db);
	return &db->api;
}

static void driver_mysql_deinit(struct sql_db *_db)
{
	struct mysql_db *db = (struct mysql_db *)_db;

	mysql_close(db->mysql);
	pool_unref(db->pool);
}

static int driver_mysql_do_query(struct mysql_db *db, const char *query)
{
	int i;

	for (i = 0; i < 2; i++) {
		if (!driver_mysql_connect(db))
			return 0;

		if (mysql_query(db->mysql, query) == 0)
			return 1;

		/* failed */
		switch (mysql_errno(db->mysql)) {
		case CR_SERVER_GONE_ERROR:
		case CR_SERVER_LOST:
			/* connection lost - try immediate reconnect */
			db->connected = FALSE;
			break;
		default:
			return -1;
		}
	}

	/* connected -> lost it -> connected -> lost again */
	return 0;
}

static void driver_mysql_exec(struct sql_db *_db, const char *query)
{
	struct mysql_db *db = (struct mysql_db *)_db;

	(void)driver_mysql_do_query(db, query);
}

static void driver_mysql_query(struct sql_db *_db, const char *query,
			       sql_query_callback_t *callback, void *context)
{
	struct mysql_db *db = (struct mysql_db *)_db;
	struct sql_result error_result;
	struct mysql_result result;

	switch (driver_mysql_do_query(db, query)) {
	case 0:
		/* not connected */
		callback(&sql_not_connected_result, context);
		return;

	case 1:
		/* query ok */
		memset(&result, 0, sizeof(result));
		result.api = driver_mysql_result;
		result.result = mysql_store_result(db->mysql);
		if (result.result == NULL)
			break;

		callback(&result.api, context);
                mysql_free_result(result.result);
		return;
	case -1:
		/* error */
		break;
	}

	/* error */
	error_result = driver_mysql_error_result;
	error_result.db = _db;
	callback(&error_result, context);
}

static int driver_mysql_result_next_row(struct sql_result *_result)
{
	struct mysql_result *result = (struct mysql_result *)_result;

	result->row = mysql_fetch_row(result->result);
	return result->row != NULL;
}

static void driver_mysql_result_fetch_fields(struct mysql_result *result)
{
	if (result->fields != NULL)
		return;

	result->fields_count = mysql_num_fields(result->result);
	result->fields = mysql_fetch_fields(result->result);
}

static unsigned int
driver_mysql_result_get_fields_count(struct sql_result *_result)
{
	struct mysql_result *result = (struct mysql_result *)_result;

        driver_mysql_result_fetch_fields(result);
	return result->fields_count;
}

static const char *
driver_mysql_result_get_field_name(struct sql_result *_result, unsigned int idx)
{
	struct mysql_result *result = (struct mysql_result *)_result;

	driver_mysql_result_fetch_fields(result);
	i_assert(idx < result->fields_count);
	return result->fields[idx].name;
}

static int driver_mysql_result_find_field(struct sql_result *_result,
					  const char *field_name)
{
	struct mysql_result *result = (struct mysql_result *)_result;
	unsigned int i;

	driver_mysql_result_fetch_fields(result);
	for (i = 0; i < result->fields_count; i++) {
		if (strcmp(result->fields[i].name, field_name) == 0)
			return i;
	}
	return -1;
}

static const char *
driver_mysql_result_get_field_value(struct sql_result *_result,
				    unsigned int idx)
{
	struct mysql_result *result = (struct mysql_result *)_result;

	return (const char *)result->row[idx];
}

static const char *
driver_mysql_result_find_field_value(struct sql_result *result,
				     const char *field_name)
{
	int idx;

	idx = driver_mysql_result_find_field(result, field_name);
	if (idx < 0)
		return NULL;
	return driver_mysql_result_get_field_value(result, idx);
}

static const char *const *
driver_mysql_result_get_values(struct sql_result *_result)
{
	struct mysql_result *result = (struct mysql_result *)_result;

	return (const char *const *)result->row;
}

static const char *driver_mysql_result_get_error(struct sql_result *result)
{
	struct mysql_db *db = (struct mysql_db *)result->db;

	return mysql_error(db->mysql);
}

struct sql_db driver_mysql_db = {
	driver_mysql_init,
	driver_mysql_deinit,
	driver_mysql_exec,
	driver_mysql_query
};

struct sql_result driver_mysql_result = {
	NULL,

	driver_mysql_result_next_row,
	driver_mysql_result_get_fields_count,
	driver_mysql_result_get_field_name,
	driver_mysql_result_find_field,
	driver_mysql_result_get_field_value,
	driver_mysql_result_find_field_value,
	driver_mysql_result_get_values,
	driver_mysql_result_get_error
};

static int
driver_mysql_result_error_next_row(struct sql_result *result __attr_unused__)
{
	return -1;
}

struct sql_result driver_mysql_error_result = {
	NULL,

	driver_mysql_result_error_next_row,
	NULL, NULL, NULL, NULL, NULL, NULL,
	driver_mysql_result_get_error
};
#endif
