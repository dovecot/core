#ifndef DSASL_CLIENT_H
#define DSASL_CLIENT_H

#include "iostream-ssl.h"
#include "sasl-common.h"

struct dsasl_client;
struct dsasl_client_session;

enum dsasl_client_result {
	DSASL_CLIENT_RESULT_OK,
	/* The final response from server returned a failed authentication.
	   The error string contains details. */
	DSASL_CLIENT_RESULT_AUTH_FAILED,
	/* Remote server sent invalid SASL protocol input */
	DSASL_CLIENT_RESULT_ERR_PROTOCOL,
	/* Internal client error */
	DSASL_CLIENT_RESULT_ERR_INTERNAL,
};

/* Session parameters */
struct dsasl_client_parameters {
        /* protocol using SASL */
        const char *protocol;
        /* host name */
        const char *host;
        /* port */
        in_port_t port;

	/* sasl mechanisms supported by server */
	const char *const *server_mechanisms;
};

struct dsasl_client_settings {
	/* Name of the SASL mechanism */
	const char *mechanism;

	/* authentication ID - must be set with most mechanisms */
	const char *authid;
	/* authorization ID (who to log in as, if authentication ID is a
	   master user) */
	const char *authzid;
	/* password - must be set with most mechanisms */
	const char *password;
};

typedef int
dsasl_client_channel_binding_callback_t(const char *type, void *context,
					const buffer_t **data_r,
					const char **error_r);

/*
 * Client
 */

struct dsasl_client *dsasl_client_create(struct event *event_parent);
void dsasl_client_ref(struct dsasl_client *client);
void dsasl_client_unref(struct dsasl_client **_client);

/* PLAIN mechanism always exists and can be accessed directly via this. */
extern const struct dsasl_client_mech dsasl_client_mech_plain;

const struct dsasl_client_mech *
dsasl_client_mech_find(struct dsasl_client *client, const char *name);
const char *dsasl_client_mech_get_name(const struct dsasl_client_mech *mech);
bool dsasl_client_mech_uses_password(const struct dsasl_client_mech *mech);

void dsasl_client_init_gssapi(struct dsasl_client *client);

/*
 * Session
 */

int dsasl_client_session_create(struct dsasl_client *client,
				struct event *event_parent,
				const struct dsasl_client_parameters *params,
				const struct dsasl_client_settings *set,
				struct dsasl_client_session **session_r,
				const char **error_r);
void dsasl_client_session_ref(struct dsasl_client_session *session);
void dsasl_client_session_unref(struct dsasl_client_session **_session);
void dsasl_client_session_destroy(struct dsasl_client_session **_session);

const char *
dsasl_client_session_get_mech_name(struct dsasl_client_session *session);

/* Enable channel binding support for this session. */
void dsasl_client_session_enable_channel_binding(
	struct dsasl_client_session *session,
	enum ssl_iostream_protocol_version channel_version,
	dsasl_client_channel_binding_callback_t *callback, void *context);

/* Call for server input. */
enum dsasl_client_result
dsasl_client_session_input(struct dsasl_client_session *session,
			   const unsigned char *input, size_t input_len,
			   const char **error_r);
/* Call for getting server output. Also used to get the initial SASL response
   if supported by the protocol. */
enum dsasl_client_result
dsasl_client_session_output(struct dsasl_client_session *session,
			    const unsigned char **output_r, size_t *output_len_r,
			    const char **error_r);

/* Call for getting extra result information.
  -1 = error, 0 = not found, 1 = ok */
int dsasl_client_session_get_result(struct dsasl_client_session *session,
				    const char *key, const char **value_r,
				    const char **error_r);

#endif
