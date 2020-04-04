#ifndef MASTER_LOGIN_AUTH_H
#define MASTER_LOGIN_AUTH_H

struct master_auth_request;

typedef void
master_login_auth_request_callback_t(const char *const *auth_args,
				     const char *errormsg, void *context);

struct master_login_auth *
master_login_auth_init(const char *auth_socket_path, bool request_auth_token);
void master_login_auth_deinit(struct master_login_auth **auth);
void master_login_auth_disconnect(struct master_login_auth *auth);

/* Set timeout for requests. */
void master_login_auth_set_timeout(struct master_login_auth *auth,
				   unsigned int msecs);

/* req has been sent by login process. this function finishes authentication
   by performing verifying from auth that req is valid and doing the userdb
   lookup. */
void master_login_auth_request(struct master_login_auth *auth,
			       const struct master_auth_request *req,
			       master_login_auth_request_callback_t *callback,
			       void *context);
unsigned int master_login_auth_request_count(struct master_login_auth *auth);

#endif
