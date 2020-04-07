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

static HASH_TABLE(char *, struct auth_request *) otp_lock_table;

void otp_lock_init(void)
{
	if (hash_table_is_created(otp_lock_table))
		return;

	hash_table_create(&otp_lock_table, default_pool, 128,
			  strcase_hash, strcasecmp);
}

bool otp_try_lock(struct auth_request *auth_request)
{
	if (hash_table_lookup(otp_lock_table, auth_request->user) != NULL)
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
		auth_request_success(auth_request, "", 0);
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

void mech_otp_deinit(void)
{
	hash_table_destroy(&otp_lock_table);
}
