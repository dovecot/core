#ifndef SASL_SERVER_PRIVATE_H
#define SASL_SERVER_PRIVATE_H

#include "sasl-server-protected.h"

extern struct event_category event_category_sasl_server;

enum sasl_server_passdb_type {
	SASL_SERVER_PASSDB_TYPE_VERIFY_PLAIN,
	SASL_SERVER_PASSDB_TYPE_LOOKUP_CREDENTIALS,
	SASL_SERVER_PASSDB_TYPE_SET_CREDENTIALS,
};

struct sasl_server_request {
	pool_t pool;
	int refcount;
	struct sasl_server_instance *sinst;
	struct sasl_server_req_ctx *rctx;
	struct sasl_server_mech_request *mech;
	struct event *event;

	enum sasl_server_request_state state;
	unsigned int sequence;

	enum sasl_server_passdb_type passdb_type;
	sasl_server_mech_passdb_callback_t *passdb_callback;

	bool failed:1;
	bool finished_with_data:1;
};

struct sasl_server_mech_reg {
	struct sasl_server_mech *mech;
	struct sasl_server_mech_reg *prev, *next;

	struct sasl_server_mech_def_reg *def_reg;
	struct sasl_server_mech_reg *def_prev, *def_next;
};

struct sasl_server_mech_def_reg {
	const struct sasl_server_mech_def *def;
	unsigned int refcount;
	struct sasl_server_mech_def_reg *prev, *next;

	struct sasl_server_mech_data *data;

	struct sasl_server_mech_reg *insts;
};

struct sasl_server_instance {
	struct sasl_server *server;
	pool_t pool;
	int refcount;
	struct sasl_server_instance *prev, *next;
	struct event *event;
	struct sasl_server_settings set;

	struct sasl_server_mech_reg *mechs_head, *mechs_tail;
	struct sasl_server_mech_reg *mechs_hidden;

	unsigned int requests;
};

struct sasl_server {
	pool_t pool;
	struct event *event;
	const struct sasl_server_request_funcs *funcs;

	struct sasl_server_instance *instances;

	struct sasl_server_mech_def_reg *mechs_head, *mechs_tail;

	unsigned int requests;
};

#endif
