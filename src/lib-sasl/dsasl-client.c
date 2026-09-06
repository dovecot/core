/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "str.h"
#include "array.h"
#include "safe-memset.h"
#include "settings.h"
#include "dsasl-client-private.h"

struct event_category event_category_sasl_client = {
	.name = "sasl-client"
};

/*
 * Client
 */

static const struct dsasl_client_mech *const core_mechanisms[] = {
	&dsasl_client_mech_anonymous,
	&dsasl_client_mech_external,
	&dsasl_client_mech_plain,
	&dsasl_client_mech_login,
	&dsasl_client_mech_digest_md5,
	&dsasl_client_mech_cram_md5,
	&dsasl_client_mech_oauthbearer,
	&dsasl_client_mech_xoauth2,
	&dsasl_client_mech_scram_sha_1,
	&dsasl_client_mech_scram_sha_1_plus,
	&dsasl_client_mech_scram_sha_256,
	&dsasl_client_mech_scram_sha_256_plus,
};

struct dsasl_client *dsasl_client_create(struct event *event_parent)
{
	pool_t pool;
	struct dsasl_client *client;
	unsigned int i;

	pool = pool_alloconly_create("sasl client", 512);
	client = p_new(pool, struct dsasl_client, 1);
	client->pool = pool;
	client->refcount = 1;

	client->event = event_create(event_parent);
	event_add_category(client->event, &event_category_sasl_client);
	event_set_append_log_prefix(client->event, "sasl: ");

	i_array_init(&client->mechanisms, N_ELEMENTS(core_mechanisms) + 4);
	for (i = 0; i < N_ELEMENTS(core_mechanisms); i++)
		dsasl_client_mech_register(client, core_mechanisms[i]);

	return client;
}

void dsasl_client_ref(struct dsasl_client *client)
{
	i_assert(client->refcount > 0);
	client->refcount++;
}

void dsasl_client_unref(struct dsasl_client **_client)
{
	struct dsasl_client *client = *_client;

	if (client == NULL)
		return;
	*_client = NULL;

	i_assert(client->refcount > 0);
	if (--client->refcount > 0)
		return;

	array_free(&client->mechanisms);
	event_unref(&client->event);
	pool_unref(&client->pool);
}

static const struct dsasl_client_mech *
dsasl_client_mech_find_idx(struct dsasl_client *client, const char *name,
			   unsigned int *idx_r)
{
	const struct dsasl_client_mech *const *mechp;

	array_foreach(&client->mechanisms, mechp) {
		if (strcasecmp((*mechp)->name, name) == 0) {
			*idx_r = array_foreach_idx(&client->mechanisms, mechp);
			return *mechp;
		}
	}
	return NULL;
}

static const struct dsasl_client_mech *
dsasl_client_mech_find(struct dsasl_client *client, const char *name)
{
	unsigned int idx;

	return dsasl_client_mech_find_idx(client, name, &idx);
}

static bool
dsasl_client_mech_uses_password(const struct dsasl_client_mech *mech)
{
	return (mech->flags & DSASL_MECH_SEC_NO_PASSWORD) == 0;
}

void dsasl_client_mech_register(struct dsasl_client *client,
				const struct dsasl_client_mech *mech)
{
	unsigned int idx;

	if (dsasl_client_mech_find_idx(client, mech->name, &idx) != NULL) {
		/* allow plugins to override the default mechanisms */
		array_delete(&client->mechanisms, idx, 1);
	}
	array_push_back(&client->mechanisms, &mech);
}

void dsasl_client_mech_unregister(struct dsasl_client *client,
				  const struct dsasl_client_mech *mech)
{
	unsigned int idx;

	if (dsasl_client_mech_find_idx(client, mech->name, &idx) == NULL)
		i_panic("SASL mechanism not registered: %s", mech->name);
	array_delete(&client->mechanisms, idx, 1);
}

static int
dsasl_client_check_mech_name(const char *mech_name, const char **error_r)
{
	if (!sasl_mechanism_name_is_valid(t_str_ucase(mech_name))) {
		*error_r = t_strdup_printf(
			"Configured SASL mechanism has invalid name '%s'",
			mech_name);
		return -1;
	}
	return 0;
}

static int
dsasl_client_require_mech(struct dsasl_client *client, const char *mech_name,
			  const struct dsasl_client_mech **mech_r,
			  const char **error_r)
{
	const struct dsasl_client_mech *mech;

	*mech_r = NULL;
	*error_r = NULL;

	mech = dsasl_client_mech_find(client, mech_name);
	if (mech != NULL) {
		*mech_r = mech;
		return 0;
	}

	/* Not supported by client */
	*error_r = t_strdup_printf(
		"Configured SASL mechanism '%s' is not supported by client",
		mech_name);
	return -1;
}

static int
dsasl_client_mech_require_password(const struct dsasl_client_mech *mech,
				   const struct client_auth_settings *mech_set,
				   const char **error_r)
{
	if (dsasl_client_mech_uses_password(mech) &&
	    *mech_set->password == '\0') {
		*error_r = "Missing client_auth_password";
		return -1;
	}
	return 0;
}

int dsasl_client_check_settings(struct dsasl_client *client,
				const char **error_r)
{
	const struct client_auth_settings *set;
	const char *mech_name;

	if (settings_get(client->event, &client_auth_setting_parser_info, 0,
			 &set, error_r) < 0)
		return -1;

	if (array_is_empty(&set->mechanisms)) {
		const struct dsasl_client_mech *mech;

		if (*set->mechanism == '\0') {
			settings_free(set);
			return 0;
		}

		/* Mechanism set explicitly */
		if (dsasl_client_check_mech_name(set->mechanism,
						 error_r) < 0 ||
		    dsasl_client_require_mech(client, set->mechanism,
					      &mech, error_r) < 0 ||
		    dsasl_client_mech_require_password(mech, set,
						       error_r) < 0) {
			settings_free(set);
			return -1;
		}
		settings_free(set);
		return 0;
	}

	array_foreach_elem(&set->mechanisms, mech_name) {
		const struct client_auth_settings *mech_set = NULL;
		const struct dsasl_client_mech *mech;

		if (dsasl_client_check_mech_name(mech_name, error_r) < 0 ||
		    settings_get_filter(client->event,
					CLIENT_AUTH_SETTINGS_FILTER, mech_name,
					&client_auth_setting_parser_info, 0,
					&mech_set, error_r) < 0 ||
		    dsasl_client_require_mech(client, mech_name,
					      &mech, error_r) < 0 ||
		    dsasl_client_mech_require_password(mech, mech_set,
						       error_r) < 0) {
			settings_free(set);
			settings_free(mech_set);
			return -1;
		}
		settings_free(mech_set);
	}

	settings_free(set);
	return 0;
}

/*
 * Session
 */

int dsasl_client_session_check_authid(
	struct dsasl_client_mech_session *msession, const char **error_r)
{
	if (msession->authid == NULL) {
		*error_r = t_strdup_printf(
			"No authentication or authorization identity configured for the %s mechanism "
			"(client_auth_authzid and client_auth_authid settings are empty)",
			msession->mech->name);
		return -1;
	}
	return 0;
}

int dsasl_client_session_check_password(
	struct dsasl_client_mech_session *msession, const char **error_r)
{
	if (msession->password == NULL) {
		*error_r = "No password configured "
			"(client_auth_password setting)";
		return -1;
	}
	return 0;
}

static bool
dsasl_client_check_server_support(const struct dsasl_client_parameters *params,
				  const char *mech_name)
{
	if (params == NULL || params->server_mechanisms == NULL)
		return TRUE;

	return str_array_icase_find(params->server_mechanisms, mech_name);
}

static int
dsasl_client_session_select_mech(struct dsasl_client *client,
				 struct event *event, pool_t pool,
				 const struct dsasl_client_parameters *params,
				 const struct client_auth_settings *set,
				 const struct dsasl_client_mech **mech_r,
				 const struct client_auth_settings **set_r,
				 const char **error_r)
{
	*mech_r = NULL;
	*set_r = NULL;
	*error_r = NULL;

	if (set->pool == NULL || array_is_empty(&set->mechanisms)) {
		if (set->mechanism != NULL && *set->mechanism != '\0') {
			/* Mechanism set explicitly;
			   Don't check server support
			 */
			if (dsasl_client_check_mech_name(set->mechanism,
							 error_r) < 0)
				return -1;
			if (dsasl_client_require_mech(client, set->mechanism,
						      mech_r, error_r) < 0)
				return -1;
			*set_r = client_auth_settings_ref(pool, set);
			return 1;
		}

		if ((set->authid == NULL || *set->authid == '\0') &&
		    (set->authzid == NULL || *set->authzid == '\0')) {
			e_debug(event, "Authentication not configured");
			*error_r = "Authentication not configured";
			return 0;
		}

		if (dsasl_client_check_server_support(params, "PLAIN")) {
			/* Either server support is unknown or PLAIN is
			   supported by server. Use it as the default. */
			*mech_r = &dsasl_client_mech_plain;
			*set_r = client_auth_settings_ref(pool, set);
			return 1;
		}

		/* Check whether we support any suitable mechanism offered by
		   the server.
		 */
		const char *const *mech_p = params->server_mechanisms;
		const struct dsasl_client_mech *mech;

		while (*mech_p != NULL) {
			mech = dsasl_client_mech_find(client, *mech_p);
			if (mech != NULL &&
			    HAS_NO_BITS(mech->flags,
					DSASL_MECH_SEC_NO_PASSWORD)) {
				*mech_r = mech;
				*set_r = client_auth_settings_ref(pool, set);
				return 1;
			}
			mech_p++;
		}

		*error_r = t_strdup_printf(
			"No suitable SASL mechanism offered by the server "
			"(configured: none, offered: %s)",
			t_strarray_join(params->server_mechanisms, ", "));
		return -1;
	}

	/* Select first suitable mechanism */
	const char *mech_name;
	array_foreach_elem(&set->mechanisms, mech_name) {
		if (dsasl_client_check_mech_name(mech_name, error_r) < 0)
			return -1;
		if (!dsasl_client_check_server_support(params, mech_name)) {
			/* Not supported by server */
			continue;
		}

		if (settings_get_filter(event,
					CLIENT_AUTH_SETTINGS_FILTER, mech_name,
					&client_auth_setting_parser_info, 0,
					set_r, error_r) < 0)
			return -1;
		if (dsasl_client_require_mech(client, mech_name,
					      mech_r, error_r) < 0) {
			settings_free(*set_r);
			return -1;
		}
		return 1;
	}

	string_t *client_mechanisms = t_str_new(64);
	const char *server_mechanisms;
	array_foreach_elem(&set->mechanisms, mech_name) {
		if (str_len(client_mechanisms) > 0)
			str_append(client_mechanisms, ", ");
		str_append(client_mechanisms, mech_name);
	}
	if (params == NULL || params->server_mechanisms == NULL)
		server_mechanisms = "unknown";
	else if (*params->server_mechanisms == NULL)
		server_mechanisms = "none";
	else {
		server_mechanisms =
			t_strarray_join(params->server_mechanisms, ", ");
	}
	*error_r = t_strdup_printf(
		"No configured SASL mechanism is offered by the server "
		"(configured: %s, offered: %s)",
		str_c(client_mechanisms), server_mechanisms);
	return -1;
}

static struct event *
dsasl_client_session_create_event(struct dsasl_client *client,
				  struct event *event_parent)
{
	struct event *event;

	if (event_parent == NULL) {
		event = event_create(client->event);
		event_drop_parent_log_prefixes(event, 1);
	} else {
		event = event_create(event_parent);
		event_add_category(event, &event_category_sasl_client);
	}
	event_set_append_log_prefix(event, "sasl: ");

	return event;
}

static int
dsasl_client_session_create_common(
	struct dsasl_client *client, struct event *event,
	const struct dsasl_client_parameters *params,
	const struct client_auth_settings *set_mult,
	struct dsasl_client_session **session_r, const char **error_r)
{
	*session_r = NULL;
	*error_r = NULL;

	const struct client_auth_settings *set;
	const struct dsasl_client_mech *mech;
	pool_t pool;
	int ret;

	pool = pool_alloconly_create("sasl client session", 1024);
	ret = dsasl_client_session_select_mech(client, event, pool,
					       params, set_mult,
					       &mech, &set, error_r);
	if (ret <= 0) {
		pool_unref(&pool);
		return ret;
	}

	const char *authid = set->authid;
	const char *authzid = set->authzid;
	const char *password = set->password;

	if (authid != NULL && *authid == '\0')
		authid = NULL;
	if (authzid != NULL && *authzid == '\0')
		authzid = NULL;
	if (!set->manual && password != NULL && *password == '\0')
		password = NULL;
	if (null_strcmp(authzid, authid) == 0)
		authzid = NULL;
	if (authid == NULL) {
		authid = authzid;
		authzid = NULL;
	}

	event_ref(event);
	event_set_append_log_prefix(event,
		t_strdup_printf("sasl(%s): ", t_str_lcase(mech->name)));
	settings_event_add_list_filter_name(event, CLIENT_AUTH_SETTINGS_FILTER,
					    mech->name);

	struct dsasl_client_session *session;

	session = p_new(pool, struct dsasl_client_session, 1);
	session->pool = pool;
	session->refcount = 1;
	session->event = event;
	session->client = client;
	dsasl_client_ref(client);

	struct dsasl_client_mech_session *msession;

	if (mech->auth_new != NULL)
		msession = mech->auth_new(pool);
	else
		msession = p_new(pool, struct dsasl_client_mech_session, 1);
	msession->pool = pool;
	msession->event = event;
	msession->mech = mech;
	msession->set = set;
	msession->session = session;
	msession->authid = authid;
	msession->authzid = authzid;
	msession->password = password;
	session->mech = msession;

	if (params != NULL) {
		msession->params.protocol = p_strdup_empty(pool, params->protocol);
		msession->params.host = p_strdup_empty(pool, params->host);
		msession->params.port = params->port;
		msession->params.server_mechanisms =
			(params->server_mechanisms == NULL ? NULL :
			 p_strarray_dup(pool, params->server_mechanisms));
	}

	if (mech->auth_check != NULL &&
	    mech->auth_check(msession, error_r) < 0) {
		dsasl_client_session_destroy(&session);
		return -1;
	}

	if (msession->authzid != NULL && msession->authid != NULL) {
		e_debug(event, "Authenticating as %s on behalf of user %s",
			msession->authid, msession->authzid);
	} else if (msession->authzid != NULL || msession->authid != NULL) {
		e_debug(event, "Authenticating as %s",
			(msession->authid == NULL ?
			 msession->authzid : msession->authid));
	} else {
		e_debug(event, "Authenticating");
	}

	*session_r = session;
	return 1;
}

int dsasl_client_session_create(
	struct dsasl_client *client, struct event *event_parent,
	const struct dsasl_client_parameters *params,
	const struct client_auth_settings *set,
	struct dsasl_client_session **session_r, const char **error_r)
{
	int ret;

	*session_r = NULL;
	*error_r = NULL;

	struct event *event =
		dsasl_client_session_create_event(client, event_parent);

	ret = dsasl_client_session_create_common(client, event, params, set,
						 session_r, error_r);

	event_unref(&event);
	return ret;
}

int dsasl_client_session_create_auto(
	struct dsasl_client *client, struct event *event_parent,
	const struct dsasl_client_parameters *params,
	struct dsasl_client_session **session_r, const char **error_r)
{
	*session_r = NULL;
	*error_r = NULL;

	struct event *event =
		dsasl_client_session_create_event(client, event_parent);
	const struct client_auth_settings *set;
	int ret;

	if (settings_get(event, &client_auth_setting_parser_info, 0,
			 &set, error_r) < 0) {
		event_unref(&event);
		return -1;
	}

	ret = dsasl_client_session_create_common(client, event, params, set,
						 session_r, error_r);

	settings_free(set);
	event_unref(&event);
	return ret;
}

void dsasl_client_session_ref(struct dsasl_client_session *session)
{
	i_assert(session->refcount > 0);
	session->refcount++;
}

void dsasl_client_session_unref(struct dsasl_client_session **_session)
{
	struct dsasl_client_session *session = *_session;

	if (session == NULL)
		return;
	*_session = NULL;

	i_assert(session->refcount > 0);
	if (--session->refcount > 0)
		return;

	struct dsasl_client_mech_session *msession = session->mech;

	if (msession->mech->auth_free != NULL)
		msession->mech->auth_free(msession);
	settings_free(msession->set);
	event_unref(&session->event);
	dsasl_client_unref(&session->client);
	pool_unref(&session->pool);
}

void dsasl_client_session_destroy(struct dsasl_client_session **_session)
{
	struct dsasl_client_session *session = *_session;

	if (session == NULL)
		return;
	*_session = NULL;

	dsasl_client_session_unref(&session);
}

const char *
dsasl_client_session_get_mech_name(struct dsasl_client_session *session)
{
	return session->mech->mech->name;
}

void dsasl_client_session_enable_channel_binding(
	struct dsasl_client_session *session,
	enum ssl_iostream_protocol_version channel_version,
	dsasl_client_channel_binding_callback_t *callback, void *context)
{
	struct dsasl_client_mech_session *msession = session->mech;

	msession->channel_version = channel_version;
	session->cbinding_callback = callback;
	session->cbinding_context = context;
}

bool dsasl_client_session_channel_binding_available(
	struct dsasl_client_mech_session *msession)
{
	return (msession->channel_version != SSL_IOSTREAM_PROTOCOL_VERSION_UNKNOWN &&
		msession->session->cbinding_callback != NULL);
}

int dsasl_client_session_get_channel_binding(
	struct dsasl_client_mech_session *msession, const char *type,
	const buffer_t **data_r, const char **error_r)
{
	struct dsasl_client_session *session = msession->session;

	if (!dsasl_client_session_channel_binding_available(msession)) {
		*error_r = "Channel binding not available locally";
		return -1;
	}
	return session->cbinding_callback(type, session->cbinding_context,
					  data_r, error_r);
}

enum dsasl_client_result
dsasl_client_session_input(struct dsasl_client_session *session,
			   const unsigned char *input, size_t input_len,
			   const char **error_r)
{
	struct dsasl_client_mech_session *msession = session->mech;

	if ((msession->mech->flags & DSASL_MECH_SEC_ALLOW_NULS) == 0 &&
	    memchr(input, '\0', input_len) != NULL) {
		*error_r = "Unexpected NUL in input data";
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	if (input_len > (size_t)SASL_MAX_MESSAGE_SIZE) {
		*error_r = t_strdup_printf(
			"Excessive challenge size (> %d)",
			SASL_MAX_MESSAGE_SIZE);
		return DSASL_CLIENT_RESULT_ERR_PROTOCOL;
	}
	return msession->mech->auth_input(msession, input, input_len, error_r);
}

enum dsasl_client_result
dsasl_client_session_output(struct dsasl_client_session *session,
			    const unsigned char **output_r, size_t *output_len_r,
			    const char **error_r)
{
	struct dsasl_client_mech_session *msession = session->mech;

	return msession->mech->auth_output(msession, output_r, output_len_r,
					   error_r);
}

int dsasl_client_session_get_result(struct dsasl_client_session *session,
				    const char *key, const char **value_r,
				    const char **error_r)
{
	struct dsasl_client_mech_session *msession = session->mech;

	if (msession->mech->auth_get_result != NULL) {
		int ret = msession->mech->auth_get_result(msession, key,
							  value_r, error_r);
		i_assert(ret <= 0 || *value_r != NULL);
		i_assert(ret >= 0 || *error_r != NULL);
		return ret;
	} else
		return 0;
}
