#ifndef DIRECTOR_REQUEST_H
#define DIRECTOR_REQUEST_H

struct director;
struct director_request;

typedef void
director_request_callback(const struct ip_addr *ip, void *context);

void director_request(struct director *dir, const char *username,
		      director_request_callback *callback, void *context);
bool director_request_continue(struct director_request *request);

#endif
