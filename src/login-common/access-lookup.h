#ifndef ACCESS_LOOKUP_H
#define ACCESS_LOOKUP_H

typedef void access_lookup_callback_t(bool success, void *context);

struct access_lookup *
access_lookup(const char *path, int client_fd, const char *daemon_name,
	      access_lookup_callback_t *callback, void *context);
void access_lookup_destroy(struct access_lookup **lookup);

#endif
