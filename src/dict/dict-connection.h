#ifndef DICT_CONNECTION_H
#define DICT_CONNECTION_H

#include "dict.h"

struct dict_connection_transaction {
	unsigned int id;
	struct dict_connection *conn;
	struct dict_transaction_context *ctx;
};

struct dict_connection {
	struct dict_connection *prev, *next;
	struct dict_server *server;

	char *username;
	char *name;
	struct dict *dict;
	enum dict_data_type value_type;

	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	struct dict_iterate_context *iter_ctx;

	/* There are only a few transactions per client, so keeping them in
	   array is fast enough */
	ARRAY_DEFINE(transactions, struct dict_connection_transaction);
};

struct dict_connection *dict_connection_create(int fd);
void dict_connection_destroy(struct dict_connection *conn);

void dict_connections_destroy_all(void);

#endif
