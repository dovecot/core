/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "safe-memset.h"
#include "dsasl-client-private.h"

struct event_category event_category_sasl_client = {
	.name = "sasl-client"
};

static int init_refcount = 0;
static ARRAY(const struct dsasl_client_mech *) dsasl_mechanisms = ARRAY_INIT;

/*
 * Client
 */

static const struct dsasl_client_mech *
dsasl_client_mech_find_idx(const char *name, unsigned int *idx_r)
{
	const struct dsasl_client_mech *const *mechp;

	array_foreach(&dsasl_mechanisms, mechp) {
		if (strcasecmp((*mechp)->name, name) == 0) {
			*idx_r = array_foreach_idx(&dsasl_mechanisms, mechp);
			return *mechp;
		}
	}
	return NULL;
}

const struct dsasl_client_mech *dsasl_client_mech_find(const char *name)
{
	unsigned int idx;

	return dsasl_client_mech_find_idx(name, &idx);
}

const char *dsasl_client_mech_get_name(const struct dsasl_client_mech *mech)
{
	return mech->name;
}

bool dsasl_client_mech_uses_password(const struct dsasl_client_mech *mech)
{
	return (mech->flags & DSASL_MECH_SEC_NO_PASSWORD) == 0;
}

void dsasl_client_mech_register(const struct dsasl_client_mech *mech)
{
	unsigned int idx;

	if (dsasl_client_mech_find_idx(mech->name, &idx) != NULL) {
		/* allow plugins to override the default mechanisms */
		array_delete(&dsasl_mechanisms, idx, 1);
	}
	array_push_back(&dsasl_mechanisms, &mech);
}

void dsasl_client_mech_unregister(const struct dsasl_client_mech *mech)
{
	unsigned int idx;

	if (dsasl_client_mech_find_idx(mech->name, &idx) == NULL)
		i_panic("SASL mechanism not registered: %s", mech->name);
	array_delete(&dsasl_mechanisms, idx, 1);
}

/*
 * Session
 */

struct dsasl_client_session *
dsasl_client_session_create(const struct dsasl_client_mech *mech,
			    const struct dsasl_client_settings *set)
{
	struct event *event;

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

	struct dsasl_client_mech_session *msession;

	msession = p_malloc(pool, mech->struct_size);
	msession->pool = pool;
	msession->event = event;
	msession->mech = mech;
	msession->set.authid = p_strdup(pool, set->authid);
	msession->set.authzid = p_strdup(pool, set->authzid);
	msession->password = p_strdup(pool, set->password);
	msession->set.password = msession->password;
	msession->set.protocol = p_strdup(pool, set->protocol);
	msession->set.host = p_strdup(pool, set->host);
	msession->set.port = set->port;
	msession->session = session;
	session->mech = msession;

	return session;
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

	if (msession->mech->free != NULL)
		msession->mech->free(msession);
	if (msession->password != NULL)
		safe_memset(msession->password, 0, strlen(msession->password));
	event_unref(&session->event);
	pool_unref(&session->pool);
}

void dsasl_client_session_destroy(struct dsasl_client_session **_session)
{
	struct dsasl_client_session *session = *_session;

	if (session == NULL)
		return;
	*_session = NULL;

	struct dsasl_client_mech_session *msession = session->mech;

	if (msession->password != NULL)
		safe_memset(msession->password, 0, strlen(msession->password));

	dsasl_client_session_unref(&session);
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
	return msession->mech->input(msession, input, input_len, error_r);
}

enum dsasl_client_result
dsasl_client_session_output(struct dsasl_client_session *session,
			    const unsigned char **output_r, size_t *output_len_r,
			    const char **error_r)
{
	struct dsasl_client_mech_session *msession = session->mech;

	return msession->mech->output(msession, output_r, output_len_r,
				      error_r);
}

int dsasl_client_set_parameter(struct dsasl_client_session *session,
			       const char *param, const char *value,
			       const char **error_r)
{
	struct dsasl_client_mech_session *msession = session->mech;

	if (msession->mech->set_parameter != NULL) {
		int ret = msession->mech->set_parameter(msession, param,
							value, error_r);
		i_assert(ret >= 0 || *error_r != NULL);
		return ret;
	} else
		return 0;
}

int dsasl_client_session_get_result(struct dsasl_client_session *session,
				    const char *key, const char **value_r,
				    const char **error_r)
{
	struct dsasl_client_mech_session *msession = session->mech;

	if (msession->mech->get_result != NULL) {
		int ret = msession->mech->get_result(msession, key,
						     value_r, error_r);
		i_assert(ret <= 0 || *value_r != NULL);
		i_assert(ret >= 0 || *error_r != NULL);
		return ret;
	} else
		return 0;
}

void dsasl_clients_init(void)
{
	if (init_refcount++ > 0)
		return;

	i_array_init(&dsasl_mechanisms, 16);
	dsasl_client_mech_register(&dsasl_client_mech_anonymous);
	dsasl_client_mech_register(&dsasl_client_mech_external);
	dsasl_client_mech_register(&dsasl_client_mech_plain);
	dsasl_client_mech_register(&dsasl_client_mech_login);
	dsasl_client_mech_register(&dsasl_client_mech_digest_md5);
	dsasl_client_mech_register(&dsasl_client_mech_cram_md5);
	dsasl_client_mech_register(&dsasl_client_mech_oauthbearer);
	dsasl_client_mech_register(&dsasl_client_mech_xoauth2);
	dsasl_client_mech_register(&dsasl_client_mech_scram_sha_1);
	dsasl_client_mech_register(&dsasl_client_mech_scram_sha_1_plus);
	dsasl_client_mech_register(&dsasl_client_mech_scram_sha_256);
	dsasl_client_mech_register(&dsasl_client_mech_scram_sha_256_plus);
}

void dsasl_clients_deinit(void)
{
	if (--init_refcount > 0)
		return;
	array_free(&dsasl_mechanisms);
}
