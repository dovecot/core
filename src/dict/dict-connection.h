#ifndef DICT_CONNECTION_H
#define DICT_CONNECTION_H

#include "dict.h"
#include "connection.h"

struct dict_connection_transaction {
	unsigned int id;
	struct dict_connection *conn;
	struct dict_transaction_context *ctx;
};

struct dict_connection {
	struct connection conn;
	struct dict_connection *prev, *next;
	struct dict_server *server;
	int refcount;

	char *username;
	char *name;
	struct dict *dict;
	enum dict_data_type value_type;

	struct timeout *to_unref;

	/* There are only a few transactions per client, so keeping them in
	   array is fast enough */
	ARRAY(struct dict_connection_transaction) transactions;
	ARRAY(struct dict_connection_cmd *) cmds;
	unsigned int async_id_counter;

	bool destroyed;
};

struct master_service_connection;

struct dict_connection *
dict_connection_create(struct master_service_connection *master_conn);

void dict_connection_ref(struct dict_connection *conn);
bool dict_connection_unref(struct dict_connection *conn);
void dict_connection_unref_safe(struct dict_connection *conn);

unsigned int dict_connections_current_count(void);
void dict_connections_init(void);
void dict_connections_destroy_all(void);

#endif
