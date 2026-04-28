/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "safe-memset.h"
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

const struct dsasl_client_mech *
dsasl_client_mech_find(struct dsasl_client *client, const char *name)
{
	unsigned int idx;

	return dsasl_client_mech_find_idx(client, name, &idx);
}

const char *dsasl_client_mech_get_name(const struct dsasl_client_mech *mech)
{
	return mech->name;
}

bool dsasl_client_mech_uses_password(const struct dsasl_client_mech *mech)
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

int dsasl_client_session_create(struct dsasl_client *client,
				const struct dsasl_client_mech *mech,
				const struct dsasl_client_parameters *params,
				const struct dsasl_client_settings *set,
				struct dsasl_client_session **session_r,
				const char **error_r)
{
	struct event *event;

	*session_r = NULL;
	*error_r = NULL;

	event = event_create(set->event_parent);

	event_add_category(event, &event_category_sasl_client);
	event_set_append_log_prefix(event,
		t_strdup_printf("sasl(%s): ", t_str_lcase(mech->name)));

	struct dsasl_client_session *session;
	pool_t pool;

	pool = pool_alloconly_create("sasl client session", 512);
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
	msession->session = session;
	msession->authid = p_strdup_empty(pool, set->authid);
	msession->authzid = p_strdup_empty(pool, set->authzid);
	msession->password = p_strdup(pool, set->password);
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

	*session_r = session;
	return 0;
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

int dsasl_client_session_get_channel_binding(
	struct dsasl_client_mech_session *msession, const char *type,
	const buffer_t **data_r, const char **error_r)
{
	struct dsasl_client_session *session = msession->session;

	if (msession->channel_version == SSL_IOSTREAM_PROTOCOL_VERSION_UNKNOWN ||
	    session->cbinding_callback == NULL) {
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
