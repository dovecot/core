#ifndef AUTH_MASTER_H
#define AUTH_MASTER_H

#include "net.h"

struct ioloop;
struct auth_master_request;
struct auth_master_reply;
struct auth_master_connection;

enum auth_master_flags {
	/* Enable logging debug information */
	AUTH_MASTER_FLAG_DEBUG			= 0x01,
	/* Don't disconnect from auth socket when idling */
	AUTH_MASTER_FLAG_NO_IDLE_TIMEOUT	= 0x02,
	/* No inner ioloop (testing only) */
	AUTH_MASTER_FLAG_NO_INNER_IOLOOP	= 0x04,
};

/*
 * Request
 */

struct auth_master_reply {
	const char *reply;
	const char *const *args;

	const char *errormsg;
};

/* Returns 1 upon full completion, 0 upon successful partial completion (will
   be called again) and -1 upon error. */
typedef int
auth_master_request_callback_t(const struct auth_master_reply *reply,
			       void *context);

struct auth_master_request *
auth_master_request(struct auth_master_connection *conn, const char *cmd,
		    const unsigned char *args, size_t args_size,
		    auth_master_request_callback_t *callback, void *context);
#define auth_master_request(conn, cmd, args, args_size, callback, context) \
	auth_master_request(conn, cmd, args, args_size + \
		CALLBACK_TYPECHECK(callback, int (*)( \
			const struct auth_master_reply *reply, \
			typeof(context))), \
		(auth_master_request_callback_t *)callback, context)

int auth_master_request_submit(struct auth_master_request **_req);

void auth_master_request_set_event(struct auth_master_request *req,
				   struct event *event);

void auth_master_request_abort(struct auth_master_request **_req);
bool auth_master_request_wait(struct auth_master_request *req);

unsigned int auth_master_request_count(struct auth_master_connection *conn);

/*
 * Connection
 */

struct auth_master_connection *
auth_master_init(const char *auth_socket_path, enum auth_master_flags flags);
void auth_master_deinit(struct auth_master_connection **conn);

int auth_master_connect(struct auth_master_connection *conn);
void auth_master_disconnect(struct auth_master_connection *conn);

/* Set timeout for lookups. */
void auth_master_set_timeout(struct auth_master_connection *conn,
			     unsigned int msecs);
/* Returns the auth_socket_path */
const char *auth_master_get_socket_path(struct auth_master_connection *conn);

void auth_master_switch_ioloop_to(struct auth_master_connection *conn,
				  struct ioloop *ioloop);
void auth_master_switch_ioloop(struct auth_master_connection *conn);

/*
 * Lookup common
 */

struct auth_user_info {
	const char *protocol;
	const char *session_id;
	const char *local_name;
	struct ip_addr local_ip, remote_ip, real_local_ip, real_remote_ip;
	in_port_t local_port, remote_port, real_local_port, real_remote_port;
	const char *const *forward_fields;
	ARRAY_TYPE(const_string) extra_fields;
	bool debug;
};

/*
 * PassDB
 */

/* Do a PASS lookup (the actual password isn't returned). */
int auth_master_pass_lookup(struct auth_master_connection *conn,
			    const char *user, const struct auth_user_info *info,
			    pool_t pool, const char *const **fields_r);

/*
 * UserDB
 */

struct auth_user_reply {
	uid_t uid;
	gid_t gid;
	const char *home, *chroot;
	ARRAY_TYPE(const_string) extra_fields;
	bool anonymous:1;
};

/* Do a USER lookup. Returns -2 = user-specific error, -1 = internal error,
   0 = user not found, 1 = ok. When returning -1 and fields[0] isn't NULL, it
   contains an error message that should be shown to user. */
int auth_master_user_lookup(struct auth_master_connection *conn,
			    const char *user, const struct auth_user_info *info,
			    pool_t pool, const char **username_r,
			    const char *const **fields_r);

/* Parse userdb extra fields into auth_user_reply structure. */
int auth_user_fields_parse(const char *const *fields, pool_t pool,
			   struct auth_user_reply *reply_r, const char **error_r);

/* Iterate through all users. If user_mask is non-NULL, it contains a string
   with wildcards ('*', '?') that the auth server MAY use to limit what users
   are returned (but it may as well return all users anyway). */
struct auth_master_user_list_ctx *
auth_master_user_list_init(struct auth_master_connection *conn,
			   const char *user_mask,
			   const struct auth_user_info *info) ATTR_NULL(3);
const char *auth_master_user_list_next(struct auth_master_user_list_ctx *ctx);
/* Returns -1 if anything failed, 0 if ok */
int auth_master_user_list_deinit(struct auth_master_user_list_ctx **ctx);

/* INTERNAL: */
void auth_user_info_export(string_t *str, const struct auth_user_info *info);

/*
 * Auth cache
 */

/* Flush authentication cache for everyone (users=NULL) or only for specified
   users. Returns number of users flushed from cache. */
int auth_master_cache_flush(struct auth_master_connection *conn,
			    const char *const *users, unsigned int *count_r);

#endif
