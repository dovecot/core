#ifndef MASTER_LOGIN_H
#define MASTER_LOGIN_H

#include "master-auth.h"

struct master_login_client {
	struct master_login_connection *conn;
	int fd;

	struct master_auth_request auth_req;
	unsigned char data[FLEXIBLE_ARRAY_MEMBER];
};

typedef void
master_login_callback_t(const struct master_login_client *client,
			const char *username, const char *const *extra_fields);
typedef void
master_login_failure_callback_t(const struct master_login_client *client,
				const char *errormsg);

struct master_login *
master_login_init(struct master_service *service, const char *auth_socket_path,
		  const char *postlogin_socket_path,
		  master_login_callback_t *callback,
		  master_login_failure_callback_t *failure_callback);
void master_login_deinit(struct master_login **login);

void master_login_add(struct master_login *login, int fd);
void master_login_stop(struct master_login *login);

#endif
