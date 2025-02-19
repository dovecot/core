/* Copyright (c) 2025 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "hash-method.h"

#include "auth-digest.h"

/*
 * Processing
 */

void auth_digest_get_hash_a1_secret(const struct hash_method *hmethod,
				    const char *username, const char *realm,
				    const char *password,
				    unsigned char *digest_r)
{
	struct hash_method_context ctx;

	/* A1 = unq(username) ":" unq(realm) ":" passwd */

	hash_method_init(&ctx, hmethod);
	hash_method_loop(&ctx, username, strlen(username));
	hash_method_loop(&ctx, ":", 1);
	hash_method_loop(&ctx, realm, strlen(realm));
	hash_method_loop(&ctx, ":", 1);
	hash_method_loop(&ctx, password, strlen(password));
	hash_method_result(&ctx, digest_r);
}
