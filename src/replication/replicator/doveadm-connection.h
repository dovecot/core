#ifndef DOVEADM_CONNECTION_H
#define DOVEADM_CONNECTION_H

enum doveadm_reply {
	DOVEADM_REPLY_OK,
	DOVEADM_REPLY_FAIL,
	DOVEADM_REPLY_NOUSER
};

typedef void doveadm_callback_t(enum doveadm_reply reply, void *context);

struct doveadm_connection *doveadm_connection_init(const char *path);
void doveadm_connection_deinit(struct doveadm_connection **conn);

void doveadm_connection_sync(struct doveadm_connection *conn,
			     const char *username, bool full,
			     doveadm_callback_t *callback, void *context);
bool doveadm_connection_is_busy(struct doveadm_connection *conn);

#endif
