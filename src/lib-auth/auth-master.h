#ifndef AUTH_MASTER_H
#define AUTH_MASTER_H

#include "net.h"

enum auth_master_flags {
	/* Enable logging debug information */
	AUTH_MASTER_FLAG_DEBUG			= 0x01,
	/* Don't disconnect from auth socket when idling */
	AUTH_MASTER_FLAG_NO_IDLE_TIMEOUT	= 0x02
};

struct auth_user_info {
	const char *service;
	struct ip_addr local_ip, remote_ip, real_local_ip, real_remote_ip;
	in_port_t local_port, remote_port, real_local_port, real_remote_port;
	const char *forward_fields;
	bool debug;
};

struct auth_user_reply {
	uid_t uid;
	gid_t gid;
	const char *home, *chroot;
	ARRAY_TYPE(const_string) extra_fields;
	bool anonymous:1;
};

struct auth_master_connection *
auth_master_init(const char *auth_socket_path, enum auth_master_flags flags);
void auth_master_deinit(struct auth_master_connection **conn);

/* Set timeout for lookups. */
void auth_master_set_timeout(struct auth_master_connection *conn,
			     unsigned int msecs);

/* Returns the auth_socket_path */
const char *auth_master_get_socket_path(struct auth_master_connection *conn);

/* Do a USER lookup. Returns -2 = user-specific error, -1 = internal error,
   0 = user not found, 1 = ok. When returning -1 and fields[0] isn't NULL, it
   contains an error message that should be shown to user. */
int auth_master_user_lookup(struct auth_master_connection *conn,
			    const char *user, const struct auth_user_info *info,
			    pool_t pool, const char **username_r,
			    const char *const **fields_r);
/* Do a PASS lookup (the actual password isn't returned). */
int auth_master_pass_lookup(struct auth_master_connection *conn,
			    const char *user, const struct auth_user_info *info,
			    pool_t pool, const char *const **fields_r);
/* Flush authentication cache for everyone (users=NULL) or only for specified
   users. Returns number of users flushed from cache. */
int auth_master_cache_flush(struct auth_master_connection *conn,
			    const char *const *users, unsigned int *count_r);

/* Parse userdb extra fields into auth_user_reply structure. */
void auth_user_fields_parse(const char *const *fields, pool_t pool,
			    struct auth_user_reply *reply_r);

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
#endif
