#ifndef __AUTH_CONNECTION_H
#define __AUTH_CONNECTION_H

struct auth_request;

/* If result == AUTH_RESULT_INTERNAL_FAILURE, request may be NULL and
   reply_data_size contains the error message. */
typedef void (*auth_callback_t)(struct auth_request *request,
				unsigned int auth_process,
				enum auth_result result,
				const unsigned char *reply_data,
				size_t reply_data_size,
				const char *virtual_user,
				void *context);

struct auth_request {
        enum auth_mech mech;
        struct auth_connection *conn;

	unsigned int id;
	unsigned char cookie[AUTH_COOKIE_SIZE];

	auth_callback_t callback;
	void *context;

	unsigned int init_sent:1;
};

extern enum auth_mech available_auth_mechs;

int auth_init_request(enum auth_mech mech, auth_callback_t callback,
		      void *context, const char **error);

void auth_continue_request(struct auth_request *request,
			   const unsigned char *data, size_t data_size);

void auth_abort_request(struct auth_request *request);

void auth_connection_init(void);
void auth_connection_deinit(void);

#endif
