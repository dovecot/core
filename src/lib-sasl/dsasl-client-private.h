#ifndef DSASL_CLIENT_PRIVATE_H
#define DSASL_CLIENT_PRIVATE_H

#include "dsasl-client-protected.h"

struct module;

struct dsasl_client_session {
	pool_t pool;
	int refcount;
	struct event *event;
	struct dsasl_client *client;
	struct dsasl_client_mech_session *mech;

	dsasl_client_channel_binding_callback_t *cbinding_callback;
	void *cbinding_context;
};

struct dsasl_client {
	pool_t pool;
	int refcount;
	struct event *event;

	ARRAY(const struct dsasl_client_mech *) mechanisms;

	/* Modules loaded by dsasl_client_module_load(). Their mechanisms are in
	   the mechanisms array, so they are unloaded only after the last
	   session is gone. */
	struct module *modules;
};

/* Call equal_func with events that have the client_auth filter name of the
   mechanism. The returned values are the same as in
   dsasl_client_settings_equal(). */
int dsasl_client_mech_name_settings_equal(
	const char *mech_name, dsasl_client_mech_settings_equal_t *equal_func,
	struct event *event1, struct event *event2, const char **error_r);

/* Compare the settings that the given mechanisms read from the events. The
   returned values are the same as in dsasl_client_settings_equal(). */
int dsasl_client_mechs_settings_equal(
	const struct dsasl_client_mech *const *mechs, unsigned int count,
	struct event *event1, struct event *event2, const char **error_r);

/* A module that registers SASL mechanisms in the client. */
struct dsasl_client_module {
	/* Name of the module, e.g. "dovecot-gssapi". */
	const char *name;
	/* Symbol of the function in the module that registers the mechanisms:
	   void init(struct dsasl_client *client). */
	const char *init_symbol;
	/* Names of the mechanisms that the function registers. Ended with
	   NULL. */
	const char *const *mech_names;
	/* Compares the settings that the mechanisms read, or NULL if they
	   have none. The events have the client_auth filter name of one of
	   the mechanisms. */
	dsasl_client_mech_settings_equal_t *settings_equal;
};

/* Load the module and register its mechanisms. The module is unloaded when
   the client is freed. Returns -1 with an error if this fails. */
int dsasl_client_module_load(struct dsasl_client *client,
			     const struct dsasl_client_module *module,
			     const char **error_r);

/* Load the module that has the mechanism, if there is one. Returns 1 if the
   module was loaded, 0 if the mechanism isn't in any module and -1 with an
   error if loading failed. */
int dsasl_client_module_load_mech(struct dsasl_client *client,
				  const char *mech_name, const char **error_r);

/* Compare the settings that the mechanisms in the modules read from the
   events. The returned values are the same as in
   dsasl_client_settings_equal(). */
int dsasl_client_module_settings_equal(struct event *event1,
				       struct event *event2,
				       const char **error_r);

#endif
