#ifndef LOGIN_SERVER_AUTH_H
#define LOGIN_SERVER_AUTH_H

/* Used for connecting to auth process via auth-master socket and sending
   REQUEST commands to finish login requests. FIXME: This should be moved
   to lib-auth/auth-master. */

struct login_request;

typedef void
login_server_auth_request_callback_t(const char *const *auth_args,
				     const char *errormsg, void *context);

struct login_server_auth *
login_server_auth_init(const char *auth_socket_path, bool request_auth_token);
void login_server_auth_deinit(struct login_server_auth **auth);
void login_server_auth_disconnect(struct login_server_auth *auth);

/* Set timeout for requests. */
void login_server_auth_set_timeout(struct login_server_auth *auth,
				   unsigned int msecs);

/* req has been sent by login process. this function finishes authentication
   by performing verifying from auth that req is valid and doing the userdb
   lookup. */
void login_server_auth_request(struct login_server_auth *auth,
			       const struct login_request *req,
			       login_server_auth_request_callback_t *callback,
			       void *context);
unsigned int login_server_auth_request_count(struct login_server_auth *auth);

#endif
