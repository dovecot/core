#ifndef LDAP_CLIENT_H
#define LDAP_CLIENT_H

enum ldap_scope {
	LDAP_SEARCH_SCOPE_BASE    = 0x0000,
	LDAP_SEARCH_SCOPE_ONE     = 0x0001,
	LDAP_SEARCH_SCOPE_SUBTREE = 0x0002
};

struct ldap_client;
struct ldap_result;
struct ldap_search_iterator;
struct ldap_entry;

/* Called when the LDAP result has finished. The callback must verify first
   if the result is valid or not by calling ldap_result_has_failed() or
   ldap_result_get_error(). The result is freed automatically after this
   callback finishes. */
typedef void ldap_result_callback_t(struct ldap_result *result, void *context);

struct ldap_client_settings {
	/* NOTE: when adding here, remember to update
	   ldap_connection_have_settings() and ldap_connection_init() */
	const char *uri;
	const char *bind_dn;
	const char *password;

	const struct ssl_iostream_settings *ssl_set;

	unsigned int timeout_secs;
	unsigned int max_idle_time_secs;
	unsigned int debug;
	bool require_ssl;
	bool start_tls;
};

struct ldap_search_input {
	const char *base_dn;
	const char *filter;
	const char *const *attributes;
	enum ldap_scope scope;

	unsigned int size_limit;

	unsigned int timeout_secs;
};

struct ldap_compare_input {
	const char *dn;
	const char *attr;
	const char *value;

	unsigned int timeout_secs;
};

/* Initialize LDAP. Returns 0 on success, or -1 and error_r if initialization
   failed with the given settings. */
int ldap_client_init(const struct ldap_client_settings *set,
		     struct ldap_client **client_r, const char **error_r);
void ldap_client_deinit(struct ldap_client **client);
void ldap_client_switch_ioloop(struct ldap_client *client);

/* Deinitialize all pooled LDAP connections if there are no references left.
   This allows freeing the memory at deinit, but still allows multiple
   independent code parts to use lib-ldap and call this function. */
void ldap_clients_cleanup(void);

void ldap_search_start(struct ldap_client *client,
		       const struct ldap_search_input *input,
		       ldap_result_callback_t *callback,
		       void *context);
#define ldap_search_start(client, input, callback, context) \
	ldap_search_start(client, input - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			struct ldap_result *, typeof(context))), \
		(ldap_result_callback_t *)callback, context)

/* Returns TRUE if the LDAP query failed and result must not be used further. */
bool ldap_result_has_failed(struct ldap_result *result);
/* Returns the error string if the query had failed, or NULL if it hasn't. */
const char *ldap_result_get_error(struct ldap_result *result);

struct ldap_search_iterator* ldap_search_iterator_init(struct ldap_result *result);
const struct ldap_entry *ldap_search_iterator_next(struct ldap_search_iterator *iter);
void ldap_search_iterator_deinit(struct ldap_search_iterator **iter);

void ldap_compare_start(struct ldap_client *client,
			const struct ldap_compare_input *input,
			ldap_result_callback_t *callback, void *context);
#define ldap_compare_start(client, input, callback, context) \
	ldap_compare_start(client, input - \
		CALLBACK_TYPECHECK(callback, void (*)( \
			struct ldap_result *, typeof(context))), \
		(ldap_result_callback_t *)callback, context)
/* Returns TRUE if the comparison matched, FALSE if not. */
bool ldap_compare_result(struct ldap_result *result);

const char *ldap_entry_dn(const struct ldap_entry *entry);
const char *const *ldap_entry_get_attributes(const struct ldap_entry *entry);
const char *const *ldap_entry_get_attribute(const struct ldap_entry *entry, const char *attribute);

#endif
