/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "safe-memset.h"
#include "dsasl-client-private.h"

struct event_category event_category_sasl_client = {
	.name = "sasl-client"
};

static int init_refcount = 0;
static ARRAY(const struct dsasl_client_mech *) dsasl_mechanisms = ARRAY_INIT;

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

struct dsasl_client *dsasl_client_new(const struct dsasl_client_mech *mech,
				      const struct dsasl_client_settings *set)
{
	struct dsasl_client *client;
	pool_t pool = pool_alloconly_create("sasl client", 512);

	client = p_malloc(pool, mech->struct_size);
	client->pool = pool;
	client->mech = mech;
	client->set.authid = p_strdup(pool, set->authid);
	client->set.authzid = p_strdup(pool, set->authzid);
	client->password = p_strdup(pool, set->password);
	client->set.password = client->password;
	client->set.protocol = p_strdup(pool, set->protocol);
	client->set.host = p_strdup(pool, set->host);
	client->set.port = set->port;

	client->event = event_create(set->event_parent);
	event_add_category(client->event, &event_category_sasl_client);
	event_set_append_log_prefix(client->event,
		t_strdup_printf("sasl(%s): ", t_str_lcase(mech->name)));

	return client;
}

void dsasl_client_free(struct dsasl_client **_client)
{
	struct dsasl_client *client = *_client;

	if (client == NULL)
		return;
	*_client = NULL;

	if (client->mech->free != NULL)
		client->mech->free(client);
	if (client->password != NULL)
		safe_memset(client->password, 0, strlen(client->password));
	event_unref(&client->event);
	pool_unref(&client->pool);
}

void dsasl_client_enable_channel_binding(
	struct dsasl_client *client,
	enum ssl_iostream_protocol_version channel_version,
	dsasl_client_channel_binding_callback_t *callback, void *context)
{
	client->channel_version = channel_version;
	client->cbinding_callback = callback;
	client->cbinding_context = context;
}

enum dsasl_client_result
dsasl_client_input(struct dsasl_client *client,
		   const unsigned char *input, size_t input_len,
		   const char **error_r)
{
	if ((client->mech->flags & DSASL_MECH_SEC_ALLOW_NULS) == 0 &&
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
	return client->mech->input(client, input, input_len, error_r);
}

enum dsasl_client_result
dsasl_client_output(struct dsasl_client *client,
		    const unsigned char **output_r, size_t *output_len_r,
		    const char **error_r)
{
	return client->mech->output(client, output_r, output_len_r, error_r);
}

int dsasl_client_set_parameter(struct dsasl_client *client,
			       const char *param, const char *value,
			       const char **error_r)
{
	if (client->mech->set_parameter != NULL) {
		int ret = client->mech->set_parameter(client, param,
						      value, error_r);
		i_assert(ret >= 0 || *error_r != NULL);
		return ret;
	} else
		return 0;
}

int dsasl_client_get_result(struct dsasl_client *client,
			    const char *key, const char **value_r,
			    const char **error_r)
{
	if (client->mech->get_result != NULL) {
		int ret =
			client->mech->get_result(client, key, value_r, error_r);
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
	dsasl_client_mech_register(&dsasl_client_mech_otp);
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
