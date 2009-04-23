#ifndef MASTER_AUTH_H
#define MASTER_AUTH_H

struct master_service;
struct master_auth_request;
struct master_auth_reply;

typedef void master_auth_callback_t(const struct master_auth_reply *reply,
				    void *context);

/* Send an authentication request. The fd contains the file descriptor to
   transfer, or -1 if no fd is wanted to be transferred. Returns tag which can
   be used to abort the request (ie. ignore the reply from master).
   request->tag is ignored. */
unsigned int master_auth_request(struct master_service *service, int fd,
				 const struct master_auth_request *request,
				 const unsigned char *data,
				 master_auth_callback_t *callback,
				 void *context);
void master_auth_request_abort(struct master_service *service,
			       unsigned int tag);

void master_auth_init(struct master_service *service);
void master_auth_deinit(struct master_service *service);

#endif
