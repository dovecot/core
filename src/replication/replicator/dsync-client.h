#ifndef DSYNC_CLIENT_H
#define DSYNC_CLIENT_H

struct dsync_client;

enum dsync_reply {
	DSYNC_REPLY_OK,
	DSYNC_REPLY_FAIL,
	DSYNC_REPLY_NOUSER,
	DSYNC_REPLY_NOREPLICATE,
};

enum dsync_type {
	DSYNC_TYPE_FULL,
	DSYNC_TYPE_NORMAL,
	DSYNC_TYPE_INCREMENTAL
};

ARRAY_DEFINE_TYPE(dsync_client, struct dsync_client *);

typedef void dsync_callback_t(enum dsync_reply reply,
			      const char *state, void *context);

struct dsync_client *
dsync_client_init(const char *path, const char *dsync_params);
void dsync_client_deinit(struct dsync_client **conn);

void dsync_client_sync(struct dsync_client *conn,
		       const char *username, const char *state, bool full,
		       dsync_callback_t *callback, void *context);
bool dsync_client_is_busy(struct dsync_client *conn);

const char *dsync_client_get_username(struct dsync_client *conn);
enum dsync_type dsync_client_get_type(struct dsync_client *conn);
const char *dsync_client_get_state(struct dsync_client *conn);

#endif
