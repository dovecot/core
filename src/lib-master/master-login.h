#ifndef MASTER_LOGIN_H
#define MASTER_LOGIN_H

#include "master-auth.h"

#define MASTER_POSTLOGIN_TIMEOUT_DEFAULT 60
/* base64(<IPv6><port><48bit timestamp>) + NUL */
#define LOGIN_MAX_SESSION_ID_LEN 33

struct master_login_client {
	struct master_login_connection *conn;
	int fd;

	struct master_auth_request auth_req;
	char session_id[LOGIN_MAX_SESSION_ID_LEN];
	unsigned char data[FLEXIBLE_ARRAY_MEMBER];
};

typedef void
master_login_callback_t(const struct master_login_client *client,
			const char *username, const char *const *extra_fields);
typedef void
master_login_failure_callback_t(const struct master_login_client *client,
				const char *errormsg);

struct master_login_settings {
	const char *auth_socket_path;
	const char *postlogin_socket_path;
	unsigned int postlogin_timeout_secs;

	master_login_callback_t *callback;
	master_login_failure_callback_t *failure_callback;

	unsigned int request_auth_token:1;
};

struct master_login *
master_login_init(struct master_service *service,
		  const struct master_login_settings *set);
void master_login_deinit(struct master_login **login);

void master_login_add(struct master_login *login, int fd);
void master_login_stop(struct master_login *login);

#endif
