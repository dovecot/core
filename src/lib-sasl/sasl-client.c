/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "safe-memset.h"
#include "sasl-client-private.h"

static ARRAY(const struct sasl_client_mech *) sasl_mechanisms = ARRAY_INIT;

static const struct sasl_client_mech *
sasl_client_mech_find_idx(const char *name, unsigned int *idx_r)
{
	const struct sasl_client_mech *const *mechp;

	array_foreach(&sasl_mechanisms, mechp) {
		if (strcasecmp((*mechp)->name, name) == 0) {
			*idx_r = array_foreach_idx(&sasl_mechanisms, mechp);
			return *mechp;
		}
	}
	return NULL;
}

const struct sasl_client_mech *sasl_client_mech_find(const char *name)
{
	unsigned int idx;

	return sasl_client_mech_find_idx(name, &idx);
}

const char *sasl_client_mech_get_name(const struct sasl_client_mech *mech)
{
	return mech->name;
}

void sasl_client_mech_register(const struct sasl_client_mech *mech)
{
	array_append(&sasl_mechanisms, &mech, 1);
}

void sasl_client_mech_unregister(const struct sasl_client_mech *mech)
{
	unsigned int idx;

	if (sasl_client_mech_find_idx(mech->name, &idx) == NULL)
		i_panic("SASL mechanism not registered: %s", mech->name);
	array_delete(&sasl_mechanisms, idx, 1);
}

struct sasl_client *sasl_client_new(const struct sasl_client_mech *mech,
				    const struct sasl_client_settings *set)
{
	struct sasl_client *client;
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

void sasl_client_free(struct sasl_client **_client)
{
	struct sasl_client *client = *_client;

	*_client = NULL;

	if (client->mech->free != NULL)
		client->mech->free(client);
	safe_memset(client->password, 0, strlen(client->password));
	pool_unref(&client->pool);
}

int sasl_client_input(struct sasl_client *client,
		      const unsigned char *input,
		      unsigned int input_len,
		      const char **error_r)
{
	return client->mech->input(client, input, input_len, error_r);
}

int sasl_client_output(struct sasl_client *client,
		       const unsigned char **output_r,
		       unsigned int *output_len_r,
		       const char **error_r)
{
	return client->mech->output(client, output_r, output_len_r, error_r);
}

void sasl_clients_init(void)
{
	i_array_init(&sasl_mechanisms, 8);
	sasl_client_mech_register(&sasl_client_mech_plain);
	sasl_client_mech_register(&sasl_client_mech_login);
}

void sasl_clients_deinit(void)
{
	array_free(&sasl_mechanisms);
}
