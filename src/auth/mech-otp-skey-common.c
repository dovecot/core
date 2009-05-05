/*
 * Common code for OTP and SKEY authentication mechanisms.
 *
 * Copyright (c) 2006 Andrey Panin <pazke@donpac.ru>
 *
 * This software is released under the MIT license.
 */

#include "auth-common.h"
#include "hash.h"
#include "mech.h"

#include "otp.h"
#include "mech-otp-skey-common.h"

static struct hash_table *otp_lock_table;

void otp_lock_init(void)
{
	if (otp_lock_table != NULL)
		return;

	otp_lock_table = hash_table_create(system_pool, system_pool,
					   128, strcase_hash,
					   (hash_cmp_callback_t *)strcasecmp);
}

int otp_try_lock(struct auth_request *auth_request)
{
	if (hash_table_lookup(otp_lock_table, auth_request->user))
		return FALSE;

	hash_table_insert(otp_lock_table, auth_request->user, auth_request);

	return TRUE;
}

void otp_unlock(struct auth_request *auth_request)
{
	struct otp_auth_request *request =
		(struct otp_auth_request *)auth_request;

	if (!request->lock)
		return;

	hash_table_remove(otp_lock_table, auth_request->user);
	request->lock = FALSE;
}

void otp_set_credentials_callback(bool success,
				  struct auth_request *auth_request)
{
	if (success)
		auth_request_success(auth_request, NULL, 0);
	else {
		auth_request_internal_failure(auth_request);
		otp_unlock(auth_request);
	}

	otp_unlock(auth_request);
}

void mech_otp_skey_auth_free(struct auth_request *auth_request)
{
	otp_unlock(auth_request);

	pool_unref(&auth_request->pool);
}
