#ifndef IMAP_URLAUTH_CONNECTION_H
#define IMAP_URLAUTH_CONNECTION_H

struct imap_urlauth_request;
struct imap_urlauth_fetch_reply;

typedef int
imap_urlauth_request_callback_t(struct imap_urlauth_fetch_reply *reply,
				void *context);

/* If reconnect_callback is specified, it's called when connection is lost.
   If the callback returns FALSE, reconnection isn't attempted. */
struct imap_urlauth_connection *
imap_urlauth_connection_init(const char *path, struct mail_user *user,
			     const char *session_id,
			     unsigned int idle_timeout_msecs);
void imap_urlauth_connection_deinit(struct imap_urlauth_connection **conn);

/* Connect to imap-urlauth (even if failed for previous requests). */
int imap_urlauth_connection_connect(struct imap_urlauth_connection *conn);

/* Continue after request callback returned 0 */
void imap_urlauth_connection_continue(struct imap_urlauth_connection *conn);

/* Create a new URL fetch request */
struct imap_urlauth_request *
imap_urlauth_request_new(struct imap_urlauth_connection *conn,
			 const char *target_user, const char *url,
			 enum imap_urlauth_fetch_flags flags,
			 imap_urlauth_request_callback_t *callback,
			 void *context);
/* Abort request */
void imap_urlauth_request_abort(struct imap_urlauth_connection *conn,
				struct imap_urlauth_request *urlreq);
/* Abort all requests with matching context value */
void imap_urlauth_request_abort_by_context(struct imap_urlauth_connection *conn,
					   void *context);

/* Returns TRUE if currently connected imap-urlauth service. */
bool imap_urlauth_connection_is_connected(struct imap_urlauth_connection *conn);

#endif
