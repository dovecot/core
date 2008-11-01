#ifndef AUTH_MASTER_H
#define AUTH_MASTER_H

#define AUTH_SERVICE_INTERNAL "internal"

struct auth_user_reply {
	uid_t uid;
	gid_t gid;
	const char *home, *chroot;
	ARRAY_TYPE(const_string) extra_fields;
};

struct auth_master_connection *
auth_master_init(const char *auth_socket_path, bool debug);
void auth_master_deinit(struct auth_master_connection **conn);

/* Returns -1 = error, 0 = user not found, 1 = ok */
int auth_master_user_lookup(struct auth_master_connection *conn,
			    const char *user, const char *service,
			    pool_t pool, struct auth_user_reply *reply_r);

#endif
