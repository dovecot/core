#ifndef DB_LDAP_H
#define DB_LDAP_H

/* Functions like ldap_bind() have been deprecated in OpenLDAP 2.3
   This define enables them until the code here can be refactored
   It is now set in m4/want_ldap.m4 if ldap is enabled. */
/* #define LDAP_DEPRECATED 1 */

/* Maximum number of pending requests before delaying new requests. */
#define DB_LDAP_MAX_PENDING_REQUESTS 8
/* connect() timeout to LDAP */
#define DB_LDAP_CONNECT_TIMEOUT_SECS 5
/* If LDAP connection is down, fail requests after waiting for this long. */
#define DB_LDAP_REQUEST_DISCONNECT_TIMEOUT_SECS 4
/* If request is still in queue after this many seconds and other requests
   have been replied, assume the request was lost and abort it. */
#define DB_LDAP_REQUEST_LOST_TIMEOUT_SECS 60
/* If server disconnects us, don't reconnect if no requests have been sent
   for this many seconds. */
#define DB_LDAP_IDLE_RECONNECT_SECS 60

#include <ldap.h>
#include "var-expand.h"
#include "db-ldap-settings.h"

#define DB_LDAP_ATTR_MULTI_PREFIX "+"
#define DB_LDAP_ATTR_SEPARATOR "\001"

struct auth_request;
struct ldap_connection;
struct ldap_request;

typedef void db_search_callback_t(struct ldap_connection *conn,
				  struct ldap_request *request,
				  LDAPMessage *res);

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

	/* Number of times this request has been sent to LDAP server. This
	   increases when LDAP gets disconnected and reconnect send the request
	   again. */
	unsigned int send_count;

	bool failed:1;
	/* This is to prevent double logging the result */
	bool result_logged:1;

	db_search_callback_t *callback;
	struct auth_request *auth_request;
};

struct ldap_request_named_result {
	const struct ldap_field *field;
	const char *dn;
	struct db_ldap_result *result;
};

struct ldap_request_search {
	struct ldap_request request;

	const char *base;
	const char *filter;
	const char *const *attributes; /* points to (pass|user) module attributes */
	const char *const *sensitive_attr_names;  /* same */

	struct db_ldap_result *result;
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
	struct event *event;
	char *log_prefix;

        const struct ldap_settings *set;
	const struct ssl_settings *ssl_set;

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

	bool delayed_connect;
};

struct db_ldap_field_expand_context {
	struct event *event;
	struct auth_fields *fields;
};

extern const struct var_expand_provider db_ldap_field_expand_fn_table[];

/* Send/queue request */
void db_ldap_request(struct ldap_connection *conn,
		     struct ldap_request *request);

void db_ldap_get_attribute_names(pool_t pool,
				 const ARRAY_TYPE(const_string) *attrlist,
				 const char *const **attributes_r,
				 const char *const **sensitive_r,
				 const char *skip_attr) ATTR_NULL(4,5);

struct ldap_connection *db_ldap_init(struct event *event);
void db_ldap_unref(struct ldap_connection **conn);

int db_ldap_connect(struct ldap_connection *conn);
void db_ldap_connect_delayed(struct ldap_connection *conn);

void db_ldap_enable_input(struct ldap_connection *conn, bool enable);

const char *ldap_escape(const char *str, void *context);
const char *ldap_get_error(struct ldap_connection *conn);

struct db_ldap_result_iterate_context *
db_ldap_result_iterate_init(struct ldap_connection *conn,
			    struct ldap_request_search *ldap_request,
			    LDAPMessage *res, bool skip_null_values);
bool db_ldap_result_iterate_next(struct db_ldap_result_iterate_context *ctx,
				 const char **name_r,
				 const char *const **values_r);
void db_ldap_result_iterate_deinit(struct db_ldap_result_iterate_context **ctx);

struct auth_fields *
ldap_query_get_fields(pool_t pool,
		      struct ldap_connection *conn,
		      struct ldap_request_search *ldap_request,
		      LDAPMessage *res, bool skip_null_values);
const char *db_ldap_attribute_as_multi(const char *name);

/* exposed only for unit tests */

const char *const *db_ldap_parse_attrs(const char *cstr);

void db_ldap_field_multi_expand_parse_data(
	const char *data, const char **field_name_r,
	const char **separator_r, const char **default_r);

#endif
