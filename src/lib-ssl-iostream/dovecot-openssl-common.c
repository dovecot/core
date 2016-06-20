/* Copyright (c) 2016 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "dovecot-openssl-common.h"

#include <openssl/ssl.h>
#include <openssl/engine.h>
#include <openssl/rand.h>

static int openssl_init_refcount = 0;
static ENGINE *dovecot_openssl_engine;

void dovecot_openssl_common_global_ref(void)
{
	unsigned char buf;

	if (openssl_init_refcount++ > 0)
		return;

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();

	/* PRNG initialization might want to use /dev/urandom, make sure it
	   does it before chrooting. We might not have enough entropy at
	   the first try, so this function may fail. It's still been
	   initialized though. */
	(void)RAND_bytes(&buf, 1);
}

bool dovecot_openssl_common_global_unref(void)
{
	i_assert(openssl_init_refcount > 0);

	if (--openssl_init_refcount > 0)
		return TRUE;

	if (dovecot_openssl_engine != NULL) {
		ENGINE_finish(dovecot_openssl_engine);
		dovecot_openssl_engine = NULL;
	}
#if OPENSSL_VERSION_NUMBER < 0x10001000L
	OBJ_cleanup();
#endif
#if OPENSSL_VERSION_NUMBER >= 0x10002000L
	SSL_COMP_free_compression_methods();
#endif
	ENGINE_cleanup();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	return FALSE;
}

int dovecot_openssl_common_global_set_engine(const char *engine,
					     const char **error_r)
{
	if (dovecot_openssl_engine != NULL)
		return 1;

	ENGINE_load_builtin_engines();
	dovecot_openssl_engine = ENGINE_by_id(engine);
	if (dovecot_openssl_engine == NULL) {
		*error_r = t_strdup_printf("Unknown engine '%s'", engine);
		return 0;
	}
	if (ENGINE_init(dovecot_openssl_engine) == 0) {
		*error_r = t_strdup_printf("ENGINE_init(%s) failed", engine);
		ENGINE_free(dovecot_openssl_engine);
		dovecot_openssl_engine = NULL;
		return -1;
	}
	if (ENGINE_set_default_RSA(dovecot_openssl_engine) == 0)
		i_unreached();
	if (ENGINE_set_default_DSA(dovecot_openssl_engine) == 0)
		i_unreached();
	if (ENGINE_set_default_ciphers(dovecot_openssl_engine) == 0)
		i_unreached();
	return 1;
}
