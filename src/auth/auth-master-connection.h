#ifndef AUTH_MASTER_CONNECTION_H
#define AUTH_MASTER_CONNECTION_H

struct stat;
struct auth_stream_reply;

struct auth_master_connection {
	struct connection conn;
	struct auth_master_connection *prev, *next;
	struct auth *auth;
	int refcount;

	struct master_list_iter_ctx *iter_ctx;
	/* If non-zero, allow only USER lookups whose returned uid matches
	   this uid. Don't allow LIST/PASS lookups. */
	uid_t userdb_restricted_uid;

	bool destroyed:1;
	bool userdb_only:1;
};

struct auth_master_connection *
auth_master_connection_create(struct auth *auth, int fd,
			      const char *path, const struct stat *socket_st,
			      bool userdb_only) ATTR_NULL(4);

void auth_master_connection_ref(struct auth_master_connection *conn);
void auth_master_connection_unref(struct auth_master_connection **conn);

/* Returns the master socket input line for logging: the REQUEST cookie and
   the values of secret fields are replaced with "<hidden>". Allocated from
   data stack. */
const char *auth_master_input_hide_secrets(const char *const *args);
void auth_master_request_callback(const char *reply, struct auth_master_connection *conn);

void auth_master_connections_destroy_all(void);

#endif
