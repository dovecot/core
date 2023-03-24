#ifndef LOGIN_SERVER_H
#define LOGIN_SERVER_H

/* This login-server API is used by post-login processes (e.g. imap) to accept
   a login request sent by the pre-login processes via login-client API. */

#include "login-interface.h"

#define LOGIN_SERVER_POSTLOGIN_TIMEOUT_DEFAULT 60

struct login_server_connection {
	struct login_server_connection *prev, *next;
	struct event *event;

	struct login_server *server;
	struct login_server_request *requests;
	struct timeval create_time;
	int refcount;
	int fd;
	struct io *io;
	struct ostream *output;

	bool login_success:1;
};

struct login_server_request {
	/* parent connection */
	struct login_server_connection *conn;
	/* linked list of all requests within the connection */
	struct login_server_request *prev, *next;
	/* non-NULL while running postlogin script */
	struct login_server_postlogin *postlogin_request;

	int fd;
	struct timeval create_time;

	struct login_request auth_req;
	char *session_id;
	unsigned char data[FLEXIBLE_ARRAY_MEMBER];
};

typedef void
login_server_callback_t(const struct login_server_request *request,
			const char *username, const char *const *extra_fields);
typedef void
login_server_failure_callback_t(const struct login_server_request *request,
				const char *errormsg);

struct login_server_settings {
	const char *auth_socket_path;
	const char *postlogin_socket_path;
	unsigned int postlogin_timeout_secs;

	login_server_callback_t *callback;
	login_server_failure_callback_t *failure_callback;

	bool update_proctitle:1;
	bool request_auth_token:1;
};

struct login_server *
login_server_init(struct master_service *service,
		  const struct login_server_settings *set);
void login_server_deinit(struct login_server **server);

void login_server_add(struct login_server *server, int fd);
void login_server_stop(struct login_server *server);

#endif
