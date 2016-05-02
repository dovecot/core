#ifndef LDAP_PRIVATE_H
#define LDAP_PRIVATE_H

#include "iostream-ssl.h"
#include "ldap-client.h"

#include <ldap.h>

#define DOVE_LDAP_CONTINUE 0
#define DOVE_LDAP_COMPLETE 1
#define DOVE_LDAP_REQUEUE 2

struct ldap_connection;
struct ldap_result;

struct ldap_op_queue_entry;
/* Handle an LDAP response. Returns 0 on success, otherwise the OpenLDAP error
   number. */
typedef int ldap_response_callback_t(struct ldap_connection *conn,
				     struct ldap_op_queue_entry *entry,
				     LDAPMessage *msg, bool *finished_r);
/* Send the request. Returns 0 on success, otherwise the OpenLDAP error number
   and sets error_r string. */
typedef int ldap_send_request_t(struct ldap_connection *conn,
				struct ldap_op_queue_entry *entry,
				const char **error_r);

struct ldap_op_queue_entry {
	pool_t pool;
	struct ldap_connection *conn;
	ldap_response_callback_t *internal_response_cb;
	void *ctx;

	int msgid;

	unsigned int timeout_secs;
	struct timeout *to_abort;

	ldap_send_request_t *send_request_cb;

	ldap_result_callback_t *result_callback;
	void *result_callback_ctx;

	struct {
		struct ldap_search_input search;
		struct ldap_compare_input compare;
	} input;
};

struct ldap_connection {
	pool_t pool;
	struct ldap_client *client;

	LDAP *conn;
	enum {
		LDAP_STATE_DISCONNECT,
		LDAP_STATE_TLS,
		LDAP_STATE_AUTH,
		LDAP_STATE_CONNECT
	} state;

	BerValue cred; /* needed for SASL */
	BerVarray scred;

	struct ldap_client_settings set;
	struct ssl_iostream_settings ssl_set;

	struct aqueue *request_queue;
	ARRAY(struct ldap_op_queue_entry *) request_array;

	unsigned int sent;
	unsigned int pending;

	struct io *io;
	struct timeout *to_disconnect;
	struct timeout *to_reconnect;
};

struct ldap_attribute {
	const char *name;
	ARRAY_TYPE(const_string) values;
};

struct ldap_entry {
	struct ldap_result *result;
	char *dn;
	ARRAY(struct ldap_attribute) attributes;
	const char *const *attr_names;
};

struct ldap_result {
	pool_t pool;
	struct ldap_connection *conn;

	ARRAY(struct ldap_entry) entries;
	int openldap_ret;
	bool compare_true;
	const char *error_string;
};

struct ldap_search_iterator {
	unsigned int idx;
	struct ldap_result *result;
};

int ldap_connection_init(struct ldap_client *client,
			 const struct ldap_client_settings *set,
			 struct ldap_connection **conn_r, const char **error_r);
void ldap_connection_deinit(struct ldap_connection **_conn);
void ldap_connection_switch_ioloop(struct ldap_connection *conn);
bool ldap_connection_have_settings(struct ldap_connection *conn,
				   const struct ldap_client_settings *set);

void ldap_connection_search_start(struct ldap_connection *conn,
				  const struct ldap_search_input *input,
				  ldap_result_callback_t *callback,
				  void *context);
void ldap_connection_compare_start(struct ldap_connection *conn,
				   const struct ldap_compare_input *input,
				   ldap_result_callback_t *callback,
				   void *context);

void ldap_connection_kill(struct ldap_connection *conn);
int ldap_connection_check(struct ldap_connection *conn);
void ldap_connection_queue_request(struct ldap_connection *conn, struct ldap_op_queue_entry *req);

int ldap_entry_init(struct ldap_entry *obj, struct ldap_result *result, LDAPMessage *message);

#endif
