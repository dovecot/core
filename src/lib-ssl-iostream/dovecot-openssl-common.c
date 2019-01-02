/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "randgen.h"
#include "dovecot-openssl-common.h"

#include <openssl/ssl.h>
#include <openssl/rand.h>
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>

static ENGINE *dovecot_openssl_engine;
#endif

static int openssl_init_refcount = 0;

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
			"OpenSSL: malloc(%"PRIuSIZE_T"): Out of memory", size);
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
			"OpenSSL: realloc(%"PRIuSIZE_T"): Out of memory", size);
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

	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
}

bool dovecot_openssl_common_global_unref(void)
{
	i_assert(openssl_init_refcount > 0);

	if (--openssl_init_refcount > 0)
		return TRUE;

#ifndef OPENSSL_NO_ENGINE
	if (dovecot_openssl_engine != NULL) {
		ENGINE_finish(dovecot_openssl_engine);
		dovecot_openssl_engine = NULL;
	}
#endif
	/* OBJ_cleanup() is called automatically by EVP_cleanup() in
	   newer versions. Doesn't hurt to call it anyway. */
	OBJ_cleanup();
#ifdef HAVE_SSL_COMP_FREE_COMPRESSION_METHODS
	SSL_COMP_free_compression_methods();
#endif
#ifndef OPENSSL_NO_ENGINE
	ENGINE_cleanup();
#endif
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
#ifdef HAVE_OPENSSL_AUTO_THREAD_DEINIT
	/* no cleanup needed */
#elif defined(HAVE_OPENSSL_ERR_REMOVE_THREAD_STATE)
	/* This was marked as deprecated in v1.1. */
	ERR_remove_thread_state(NULL);
#else
	/* This was deprecated by ERR_remove_thread_state(NULL) in v1.0.0. */
	ERR_remove_state(0);
#endif
	ERR_free_strings();
#ifdef HAVE_OPENSSL_CLEANUP
	OPENSSL_cleanup();
#endif
	return FALSE;
}

int dovecot_openssl_common_global_set_engine(const char *engine,
					     const char **error_r)
{
#ifndef OPENSSL_NO_ENGINE
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
	if (ENGINE_set_default(dovecot_openssl_engine, ENGINE_METHOD_ALL) == 0) {
		*error_r = t_strdup_printf("ENGINE_set_default(%s) failed", engine);
		ENGINE_free(dovecot_openssl_engine);
		dovecot_openssl_engine = NULL;
		return -1;
	}
#endif
	return 1;
}
