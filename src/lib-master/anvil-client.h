#ifndef ANVIL_CLIENT_H
#define ANVIL_CLIENT_H

#define ANVIL_DEFAULT_LOOKUP_TIMEOUT_MSECS (5*1000)
#define ANVIL_DEFAULT_KICK_TIMEOUT_MSECS (25*1000)

enum anvil_client_flags {
	/* if connect() fails with ENOENT, hide the error */
	ANVIL_CLIENT_FLAG_HIDE_ENOENT	= 0x01
};

struct anvil_client_callbacks {
	/* Called when connection is lost. If it returns FALSE, reconnection
	   isn't attempted. */
	bool (*reconnect)(void);

	/* Handle any command sent by anvil process. Send the reply with
	   anvil_client_send_reply(). The command can be processed
	   asynchronously, but the next command callback isn't called before
	   the first one is replied to. Returns TRUE if the command was handled,
	   FALSE if the command was unknown. */
	bool (*command)(const char *cmd, const char *const *args);
};

/* reply=NULL if query failed */
typedef void anvil_callback_t(const char *reply, void *context);

/* If reconnect_callback is specified, it's called when connection is lost.
   If the callback returns FALSE, reconnection isn't attempted. */
struct anvil_client *
anvil_client_init(const char *path,
		  const struct anvil_client_callbacks *callbacks,
		  enum anvil_client_flags flags) ATTR_NULL(2);
void anvil_client_deinit(struct anvil_client **client);

/* Connect to anvil. If retry=TRUE, try connecting for a while */
int anvil_client_connect(struct anvil_client *client, bool retry);

/* Send a query to anvil, expect a one line reply. The returned pointer can be
   used to abort the query later. It becomes invalid when callback is
   called (= the callback must not call it). Returns NULL if the query couldn't
   be sent. */
struct anvil_query *
anvil_client_query(struct anvil_client *client, const char *query,
		   unsigned int timeout_msecs,
		   anvil_callback_t *callback, void *context);
#define anvil_client_query(client, query, timeout_msecs, callback, context) \
	anvil_client_query(client, query, timeout_msecs, \
		(anvil_callback_t *)(callback), 1 ? (context) : \
		CALLBACK_TYPECHECK(callback, \
			void (*)(const char *, typeof(context))))
void anvil_client_query_abort(struct anvil_client *client,
			      struct anvil_query **query);
/* Send a command to anvil, don't expect any replies. */
void anvil_client_cmd(struct anvil_client *client, const char *cmd);

/* Send reply to anvil for a command from anvil_client_callbacks.command(). */
void anvil_client_send_reply(struct anvil_client *client, const char *reply);

/* Returns TRUE if anvil is connected to. */
bool anvil_client_is_connected(struct anvil_client *client);

#endif
