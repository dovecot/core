#ifndef __AUTH_CONNECTION_H
#define __AUTH_CONNECTION_H

typedef struct _AuthConnection AuthConnection;

/* If result == AUTH_RESULT_INTERNAL_FAILURE, request may be NULL and
   reply_data_size contains the error message. */
typedef void (*AuthCallback)(AuthRequest *request, int auth_process,
			     AuthResult result, const unsigned char *reply_data,
			     unsigned int reply_data_size, void *user_data);

struct _AuthRequest {
        AuthMethod method;
        AuthConnection *conn;

	int id;
	unsigned char cookie[AUTH_COOKIE_SIZE];

	AuthCallback callback;
	void *user_data;

	unsigned int init_sent:1;
};

extern AuthMethod available_auth_methods;

int auth_init_request(AuthMethod method, AuthCallback callback,
		      void *user_data, const char **error);

void auth_continue_request(AuthRequest *request, const unsigned char *data,
			   unsigned int data_size);

void auth_connection_init(void);
void auth_connection_deinit(void);

#endif
