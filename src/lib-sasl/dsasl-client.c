/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "safe-memset.h"
#include "dsasl-client-private.h"

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
	return client;
}

void dsasl_client_free(struct dsasl_client **_client)
{
	struct dsasl_client *client = *_client;

	*_client = NULL;

	if (client->mech->free != NULL)
		client->mech->free(client);
	safe_memset(client->password, 0, strlen(client->password));
	pool_unref(&client->pool);
}

int dsasl_client_input(struct dsasl_client *client,
		       const unsigned char *input, size_t input_len,
		       const char **error_r)
{
	return client->mech->input(client, input, input_len, error_r);
}

int dsasl_client_output(struct dsasl_client *client,
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

	i_array_init(&dsasl_mechanisms, 8);
	dsasl_client_mech_register(&dsasl_client_mech_external);
	dsasl_client_mech_register(&dsasl_client_mech_plain);
	dsasl_client_mech_register(&dsasl_client_mech_login);
	dsasl_client_mech_register(&dsasl_client_mech_oauthbearer);
	dsasl_client_mech_register(&dsasl_client_mech_xoauth2);
}

void dsasl_clients_deinit(void)
{
	if (--init_refcount > 0)
		return;
	array_free(&dsasl_mechanisms);
}
