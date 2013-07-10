#ifndef DB_LDAP_H
#define DB_LDAP_H

/* Functions like ldap_bind() have been deprecated in OpenLDAP 2.3
   This define enables them until the code here can be refactored */
#define LDAP_DEPRECATED 1

/* Maximum number of pending requests before delaying new requests. */
#define DB_LDAP_MAX_PENDING_REQUESTS 8
/* If LDAP connection is down, fail requests after waiting for this long. */
#define DB_LDAP_REQUEST_DISCONNECT_TIMEOUT_SECS 4
/* If request is still in queue after this many seconds and other requests
   have been replied, assume the request was lost and abort it. */
#define DB_LDAP_REQUEST_LOST_TIMEOUT_SECS 60
/* If server disconnects us, don't reconnect if no requests have been sent
   for this many seconds. */
#define DB_LDAP_IDLE_RECONNECT_SECS 60

#include <ldap.h>

struct auth_request;
struct ldap_connection;
struct ldap_request;

typedef void db_search_callback_t(struct ldap_connection *conn,
				  struct ldap_request *request,
				  LDAPMessage *res);

struct ldap_settings {
	const char *hosts;
	const char *uris;
	const char *dn;
	const char *dnpass;
	bool auth_bind;
	const char *auth_bind_userdn;

	bool tls;
	bool sasl_bind;
	const char *sasl_mech;
	const char *sasl_realm;
	const char *sasl_authz_id;

	const char *tls_ca_cert_file;
	const char *tls_ca_cert_dir;
	const char *tls_cert_file;
	const char *tls_key_file;
	const char *tls_cipher_suite;
	const char *tls_require_cert;

	const char *deref;
	const char *scope;
	const char *base;
	unsigned int ldap_version;

	const char *ldaprc_path;
	const char *debug_level;

	const char *user_attrs;
	const char *user_filter;
	const char *pass_attrs;
	const char *pass_filter;
	const char *iterate_attrs;
	const char *iterate_filter;

	const char *default_pass_scheme;
	bool userdb_warning_disable; /* deprecated for now at least */

	/* ... */
	int ldap_deref, ldap_scope;
	uid_t uid;
	gid_t gid;
};

enum ldap_request_type {
	LDAP_REQUEST_TYPE_SEARCH,
	LDAP_REQUEST_TYPE_BIND
};

struct ldap_field {
	/* Dovecot field name. */
	const char *name;
	/* Field value template with %vars. NULL = same as LDAP value. */
	const char *value;
	/* LDAP attribute name, or "" if this is a static field. */
	const char *ldap_attr_name;

	/* LDAP value contains a DN, which is looked up and used for @name
	   attributes. */
	bool value_is_dn;
	/* This attribute is used internally only via %{ldap_ptr},
	   it shouldn't be returned in iteration. */
	bool skip;
};
ARRAY_DEFINE_TYPE(ldap_field, struct ldap_field);

struct ldap_request {
	enum ldap_request_type type;

	/* msgid for sent requests, -1 if not sent */
	int msgid;
	/* timestamp when request was created */
	time_t create_time;

	bool failed;

	db_search_callback_t *callback;
	struct auth_request *auth_request;
};

struct ldap_request_named_result {
	const struct ldap_field *field;
	const char *dn;
	LDAPMessage *result;
};

struct ldap_request_search {
	struct ldap_request request;

	const char *base;
	const char *filter;
	char **attributes; /* points to pass_attr_names / user_attr_names */
	const ARRAY_TYPE(ldap_field) *attr_map;

	LDAPMessage *result;
	ARRAY(struct ldap_request_named_result) named_results;
	unsigned int name_idx;

	bool multi_entry;
};

struct ldap_request_bind {
	struct ldap_request request;

	const char *dn;
};

enum ldap_connection_state {
	/* Not connected */
	LDAP_CONN_STATE_DISCONNECTED,
	/* Binding - either to default dn or doing auth bind */
	LDAP_CONN_STATE_BINDING,
	/* Bound to auth dn */
	LDAP_CONN_STATE_BOUND_AUTH,
	/* Bound to default dn */
	LDAP_CONN_STATE_BOUND_DEFAULT
};

struct ldap_connection {
	struct ldap_connection *next;

	pool_t pool;
	int refcount;

	char *config_path;
        struct ldap_settings set;

	LDAP *ld;
	enum ldap_connection_state conn_state;
	int default_bind_msgid;

	int fd;
	struct io *io;
	struct timeout *to;

	/* Request queue contains sent requests at tail (msgid != -1) and
	   queued requests at head (msgid == -1). */
	struct aqueue *request_queue;
	ARRAY(struct ldap_request *) request_array;
	/* Number of messages in queue with msgid != -1 */
	unsigned int pending_count;

	/* Timestamp when we last received a reply */
	time_t last_reply_stamp;

	char **pass_attr_names, **user_attr_names, **iterate_attr_names;
	ARRAY_TYPE(ldap_field) pass_attr_map, user_attr_map, iterate_attr_map;
	bool userdb_used;
};

/* Send/queue request */
void db_ldap_request(struct ldap_connection *conn,
		     struct ldap_request *request);

void db_ldap_set_attrs(struct ldap_connection *conn, const char *attrlist,
		       char ***attr_names_r, ARRAY_TYPE(ldap_field) *attr_map,
		       const char *skip_attr) ATTR_NULL(5);

struct ldap_connection *db_ldap_init(const char *config_path, bool userdb);
void db_ldap_unref(struct ldap_connection **conn);

int db_ldap_connect(struct ldap_connection *conn);

void db_ldap_enable_input(struct ldap_connection *conn, bool enable);

const char *ldap_escape(const char *str,
			const struct auth_request *auth_request);
const char *ldap_get_error(struct ldap_connection *conn);

struct db_ldap_result_iterate_context *
db_ldap_result_iterate_init(struct ldap_connection *conn,
			    struct ldap_request_search *ldap_request,
			    LDAPMessage *res, bool skip_null_values);
bool db_ldap_result_iterate_next(struct db_ldap_result_iterate_context *ctx,
				 const char **name_r,
				 const char *const **values_r);
void db_ldap_result_iterate_deinit(struct db_ldap_result_iterate_context **ctx);

#endif
