#ifndef MASTER_LOGIN_H
#define MASTER_LOGIN_H

#include "master-auth.h"

#define MASTER_POSTLOGIN_TIMEOUT_DEFAULT 60

struct master_login_client {
	/* parent connection */
	struct master_login_connection *conn;
	/* linked list of all clients within the connection */
	struct master_login_client *prev, *next;
	/* non-NULL while running postlogin script */
	struct master_login_postlogin *postlogin_client;

	int fd;
	struct timeval create_time;

	struct master_auth_request auth_req;
	char *session_id;
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

	bool request_auth_token:1;
};

struct master_login *
master_login_init(struct master_service *service,
		  const struct master_login_settings *set);
void master_login_deinit(struct master_login **login);

void master_login_add(struct master_login *login, int fd);
void master_login_stop(struct master_login *login);

#endif
