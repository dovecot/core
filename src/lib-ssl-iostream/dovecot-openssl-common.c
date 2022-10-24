/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "randgen.h"
#include "dovecot-openssl-common.h"
#include "iostream-openssl.h"

#include <openssl/ssl.h>
#include <openssl/err.h>
#ifdef HAVE_OSSL_PROVIDER_try_load
#  include <openssl/provider.h>
#else
#  include <openssl/engine.h>
#endif
#include <openssl/rand.h>

static int openssl_init_refcount = 0;
#ifdef HAVE_OSSL_PROVIDER_try_load
static OSSL_PROVIDER *dovecot_openssl_engine = NULL;
#else
static ENGINE *dovecot_openssl_engine = NULL;
#endif

#ifdef HAVE_SSL_NEW_MEM_FUNCS
static void *dovecot_openssl_malloc(size_t size, const char *u0 ATTR_UNUSED, int u1 ATTR_UNUSED)
#else
static void *dovecot_openssl_malloc(size_t size)
#endif
{
	/* this may be performance critical, so don't use
	   i_malloc() or calloc() */
	void *mem = malloc(size);
	if (mem == NULL) {
		i_fatal_status(FATAL_OUTOFMEM,
			"OpenSSL: malloc(%zu): Out of memory", size);
	}
	return mem;
}

#ifdef HAVE_SSL_NEW_MEM_FUNCS
static void *dovecot_openssl_realloc(void *ptr, size_t size, const char *u0 ATTR_UNUSED, int u1 ATTR_UNUSED)
#else
static void *dovecot_openssl_realloc(void *ptr, size_t size)
#endif
{
	void *mem = realloc(ptr, size);
	if (mem == NULL) {
		i_fatal_status(FATAL_OUTOFMEM,
			"OpenSSL: realloc(%zu): Out of memory", size);
	}
	return mem;
}

#ifdef HAVE_SSL_NEW_MEM_FUNCS
static void dovecot_openssl_free(void *ptr, const char *u0 ATTR_UNUSED, int u1 ATTR_UNUSED)
#else
static void dovecot_openssl_free(void *ptr)
#endif
{
	free(ptr);
}

void dovecot_openssl_common_global_ref(void)
{
	if (openssl_init_refcount++ > 0)
		return;

	/* use our own memory allocation functions that will die instead of
	   returning NULL. this avoids random failures on out-of-memory
	   conditions. */
	if (CRYPTO_set_mem_functions(dovecot_openssl_malloc,
				     dovecot_openssl_realloc, dovecot_openssl_free) == 0) {
		/*i_warning("CRYPTO_set_mem_functions() was called too late");*/
	}

#ifdef HAVE_OPENSSL_init_ssl
	OPENSSL_init_ssl(0, NULL);
#else
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
#endif
}

bool dovecot_openssl_common_global_unref(void)
{
	i_assert(openssl_init_refcount > 0);

	if (--openssl_init_refcount > 0)
		return TRUE;

	if (dovecot_openssl_engine != NULL) {
#ifdef HAVE_OSSL_PROVIDER_try_load
		OSSL_PROVIDER_unload(dovecot_openssl_engine);
#else
		ENGINE_finish(dovecot_openssl_engine);
#endif
		dovecot_openssl_engine = NULL;
	}
#ifdef HAVE_OPENSSL_cleanup
	OPENSSL_cleanup();
#else
	/* OBJ_cleanup() is called automatically by EVP_cleanup() in
	   newer versions. Doesn't hurt to call it anyway. */
	OBJ_cleanup();
#  if !defined(OPENSSL_NO_COMP)
	SSL_COMP_free_compression_methods();
#  endif
	ENGINE_cleanup();
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#  ifdef HAVE_OPENSSL_thread_stop
	/* no cleanup needed */
#  elif defined(HAVE_ERR_remove_thread_state)
	/* This was marked as deprecated in v1.1. */
	ERR_remove_thread_state(NULL);
#  elif defined(HAVE_ERR_remove_state)
	/* This was deprecated by ERR_remove_thread_state(NULL) in v1.0.0. */
	ERR_remove_state(0);
#  endif
	ERR_free_strings();
#endif
	return FALSE;
}

int dovecot_openssl_common_global_set_engine(const char *engine,
					     const char **error_r)
{
	if (dovecot_openssl_engine != NULL)
		return 1;

#ifdef HAVE_ENGINE_by_id
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
	if (ENGINE_set_default(dovecot_openssl_engine, ENGINE_METHOD_ALL) == 0) {
		*error_r = t_strdup_printf("ENGINE_set_default(%s) failed", engine);
		ENGINE_free(dovecot_openssl_engine);
		dovecot_openssl_engine = NULL;
		return -1;
	}
#elif defined(HAVE_OSSL_PROVIDER_try_load)
	if ((dovecot_openssl_engine = OSSL_PROVIDER_try_load(NULL, engine, 1)) == NULL) {
		*error_r = t_strdup_printf("Cannot load '%s': %s", engine,
					   openssl_iostream_error());
		return 0;
	}
	return 1;
#else
	*error_r = t_strdup_printf("Cannot load '%s': No engine/provider support available", engine);
#endif
	return 1;
}
