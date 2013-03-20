#ifndef DSYNC_CLIENT_H
#define DSYNC_CLIENT_H

enum dsync_reply {
	DSYNC_REPLY_OK,
	DSYNC_REPLY_FAIL,
	DSYNC_REPLY_NOUSER
};

typedef void dsync_callback_t(enum dsync_reply reply,
			      const char *state, void *context);

struct dsync_client *dsync_client_init(const char *path);
void dsync_client_deinit(struct dsync_client **conn);

void dsync_client_sync(struct dsync_client *conn,
		       const char *username, const char *state, bool full,
		       dsync_callback_t *callback, void *context);
bool dsync_client_is_busy(struct dsync_client *conn);

#endif
