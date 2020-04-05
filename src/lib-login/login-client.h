#ifndef LOGIN_CLIENT_H
#define LOGIN_CLIENT_H

/* This login-client API is used by the untrusted pre-login processes (e.g.
   login-common). It connects to the post-login process (e.g. imap), which uses
   login-server API to handle the login request. */

#include "login-interface.h"

struct master_service;

struct login_client_request_params {
	/* Client fd to transfer to post-login process or -1 if no fd is
	   wanted to be transferred. */
	int client_fd;
	/* Override login_connection_list->default_path if non-NULL */
	const char *socket_path;

	/* Login request that is sent to post-login process.
	   tag is ignored. */
	struct login_request request;
	/* Client input of size request.data_size */
	const unsigned char *data;
};

/* reply=NULL if the login was cancelled due to some error */
typedef void login_client_request_callback_t(const struct login_reply *reply,
					     void *context);

struct login_client_list *
login_client_list_init(struct master_service *service, const char *path);
void login_client_list_deinit(struct login_client_list **list);

/* Send a login request. Returns tag which can be used to abort the
   request (ie. ignore the reply from master). */
void login_client_request(struct login_client_list *list,
			  const struct login_client_request_params *params,
			  login_client_request_callback_t *callback,
			  void *context, unsigned int *tag_r);
void login_client_request_abort(struct login_client_list *list,
				unsigned int tag);

#endif
