/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "iostream-ssl-private.h"

#define OFFSET(name) offsetof(struct ssl_iostream_settings, name)
static const size_t ssl_iostream_settings_string_offsets[] = {
	OFFSET(min_protocol),
	OFFSET(cipher_list),
	OFFSET(ciphersuites),
	OFFSET(curve_list),
	OFFSET(ca),
	OFFSET(ca_file),
	OFFSET(ca_dir),
	OFFSET(cert.cert),
	OFFSET(cert.key),
	OFFSET(cert.key_password),
	OFFSET(alt_cert.cert),
	OFFSET(alt_cert.key),
	OFFSET(alt_cert.key_password),
	OFFSET(dh),
	OFFSET(cert_username_field),
	OFFSET(crypto_device),
};

static bool ssl_module_loaded = FALSE;
#ifdef HAVE_SSL
static struct module *ssl_module = NULL;
#endif
static const struct iostream_ssl_vfuncs *ssl_vfuncs = NULL;

#ifdef HAVE_SSL
static void ssl_module_unload(void)
{
	ssl_iostream_context_cache_free();
	module_dir_unload(&ssl_module);
}
#endif

void iostream_ssl_module_init(const struct iostream_ssl_vfuncs *vfuncs)
{
	ssl_vfuncs = vfuncs;
	ssl_module_loaded = TRUE;
}

int ssl_module_load(const char **error_r)
{
#ifdef HAVE_SSL
	const char *plugin_name = "ssl_iostream_openssl";
	struct module_dir_load_settings mod_set;

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.setting_name = "<built-in lib-ssl-iostream lookup>";
	mod_set.require_init_funcs = TRUE;
	ssl_module = module_dir_load(MODULE_DIR, plugin_name, &mod_set);
	if (module_dir_try_load_missing(&ssl_module, MODULE_DIR, plugin_name,
					&mod_set, error_r) < 0)
		return -1;
	module_dir_init(ssl_module);
	if (!ssl_module_loaded) {
		*error_r = t_strdup_printf(
			"%s didn't call iostream_ssl_module_init() - SSL not initialized",
			plugin_name);
		module_dir_unload(&ssl_module);
		return -1;
	}

	/* Destroy SSL module after (most of) the others. Especially lib-fs
	   backends may still want to access SSL module in their own
	   atexit-callbacks. */
	lib_atexit_priority(ssl_module_unload, LIB_ATEXIT_PRIORITY_LOW);
	return 0;
#else
	*error_r = "SSL support not compiled in";
	return -1;
#endif
}

int io_stream_ssl_global_init(const struct ssl_iostream_settings *set,
			      const char **error_r)
{
	return ssl_vfuncs->global_init(set, error_r);
}

int ssl_iostream_context_init_client(const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r,
				     const char **error_r)
{
	struct ssl_iostream_settings set_copy = *set;

	/* ensure this is set to TRUE */
	set_copy.verify_remote_cert = TRUE;

	if (!ssl_module_loaded) {
		if (ssl_module_load(error_r) < 0)
			return -1;
	}
	if (io_stream_ssl_global_init(&set_copy, error_r) < 0)
		return -1;
	return ssl_vfuncs->context_init_client(&set_copy, ctx_r, error_r);
}

int ssl_iostream_context_init_server(const struct ssl_iostream_settings *set,
				     struct ssl_iostream_context **ctx_r,
				     const char **error_r)
{
	if (!ssl_module_loaded) {
		if (ssl_module_load(error_r) < 0)
			return -1;
	}
	if (io_stream_ssl_global_init(set, error_r) < 0)
		return -1;
	return ssl_vfuncs->context_init_server(set, ctx_r, error_r);
}

void ssl_iostream_context_ref(struct ssl_iostream_context *ctx)
{
	ssl_vfuncs->context_ref(ctx);
}

void ssl_iostream_context_unref(struct ssl_iostream_context **_ctx)
{
	struct ssl_iostream_context *ctx = *_ctx;

	*_ctx = NULL;
	ssl_vfuncs->context_unref(ctx);
}

int io_stream_create_ssl_client(struct ssl_iostream_context *ctx, const char *host,
				const struct ssl_iostream_settings *set,
				struct istream **input, struct ostream **output,
				struct ssl_iostream **iostream_r,
				const char **error_r)
{
	struct ssl_iostream_settings set_copy = *set;
	set_copy.verify_remote_cert = TRUE;
	return ssl_vfuncs->create(ctx, host, &set_copy, input, output,
				  iostream_r, error_r);
}

int io_stream_create_ssl_server(struct ssl_iostream_context *ctx,
				const struct ssl_iostream_settings *set,
				struct istream **input, struct ostream **output,
				struct ssl_iostream **iostream_r,
				const char **error_r)
{
	return ssl_vfuncs->create(ctx, NULL, set, input, output,
				  iostream_r, error_r);
}

void ssl_iostream_unref(struct ssl_iostream **_ssl_io)
{
	struct ssl_iostream *ssl_io = *_ssl_io;

	*_ssl_io = NULL;
	ssl_vfuncs->unref(ssl_io);
}

void ssl_iostream_destroy(struct ssl_iostream **_ssl_io)
{
	struct ssl_iostream *ssl_io;

	if (_ssl_io == NULL || *_ssl_io == NULL)
		return;

	ssl_io = *_ssl_io;
	*_ssl_io = NULL;
	ssl_vfuncs->destroy(ssl_io);
}

void ssl_iostream_set_log_prefix(struct ssl_iostream *ssl_io,
				 const char *prefix)
{
	ssl_vfuncs->set_log_prefix(ssl_io, prefix);
}

int ssl_iostream_handshake(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->handshake(ssl_io);
}

void ssl_iostream_set_handshake_callback(struct ssl_iostream *ssl_io,
					 ssl_iostream_handshake_callback_t *callback,
					 void *context)
{
	ssl_vfuncs->set_handshake_callback(ssl_io, callback, context);
}

void ssl_iostream_set_sni_callback(struct ssl_iostream *ssl_io,
				   ssl_iostream_sni_callback_t *callback,
				   void *context)
{
	ssl_vfuncs->set_sni_callback(ssl_io, callback, context);
}

void ssl_iostream_change_context(struct ssl_iostream *ssl_io,
				 struct ssl_iostream_context *ctx)
{
	ssl_vfuncs->change_context(ssl_io, ctx);
}

bool ssl_iostream_is_handshaked(const struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->is_handshaked(ssl_io);
}

bool ssl_iostream_has_handshake_failed(const struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->has_handshake_failed(ssl_io);
}

bool ssl_iostream_has_valid_client_cert(const struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->has_valid_client_cert(ssl_io);
}

bool ssl_iostream_has_broken_client_cert(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->has_broken_client_cert(ssl_io);
}

bool ssl_iostream_cert_match_name(struct ssl_iostream *ssl_io, const char *name,
				  const char **reason_r)
{
	return ssl_vfuncs->cert_match_name(ssl_io, name, reason_r);
}

int ssl_iostream_check_cert_validity(struct ssl_iostream *ssl_io,
				     const char *host, const char **error_r)
{
	const char *reason;

	if (!ssl_iostream_has_valid_client_cert(ssl_io)) {
		if (!ssl_iostream_has_broken_client_cert(ssl_io))
			*error_r = "SSL certificate not received";
		else {
			*error_r = t_strdup(ssl_iostream_get_last_error(ssl_io));
			if (*error_r == NULL)
				*error_r = "Received invalid SSL certificate";
		}
		return -1;
	} else if (!ssl_iostream_cert_match_name(ssl_io, host, &reason)) {
		*error_r = t_strdup_printf(
			"SSL certificate doesn't match expected host name %s: %s",
			host, reason);
		return -1;
	}
	return 0;
}

const char *ssl_iostream_get_peer_name(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_peer_name(ssl_io);
}

const char *ssl_iostream_get_server_name(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_server_name(ssl_io);
}

const char *ssl_iostream_get_compression(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_compression(ssl_io);
}

const char *ssl_iostream_get_security_string(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_security_string(ssl_io);
}

const char *ssl_iostream_get_last_error(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_last_error(ssl_io);
}

struct ssl_iostream_settings *ssl_iostream_settings_dup(pool_t pool,
			const struct ssl_iostream_settings *old_set)
{
	struct ssl_iostream_settings *new_set;

	new_set = p_new(pool, struct ssl_iostream_settings, 1);
	ssl_iostream_settings_init_from(pool, new_set, old_set);
	return new_set;
}

void ssl_iostream_settings_init_from(pool_t pool,
				     struct ssl_iostream_settings *dest,
				     const struct ssl_iostream_settings *src)
{
	unsigned int i;

	*dest = *src;
	for (i = 0; i < N_ELEMENTS(ssl_iostream_settings_string_offsets); i++) {
		const size_t offset = ssl_iostream_settings_string_offsets[i];
		const char *const *src_str = CONST_PTR_OFFSET(src, offset);
		const char **dest_str = PTR_OFFSET(dest, offset);
		*dest_str = p_strdup(pool, *src_str);
	}
}

bool ssl_iostream_settings_equals(const struct ssl_iostream_settings *set1,
				  const struct ssl_iostream_settings *set2)
{
	struct ssl_iostream_settings set1_nonstr, set2_nonstr;
	unsigned int i;

	set1_nonstr = *set1;
	set2_nonstr = *set2;
	for (i = 0; i < N_ELEMENTS(ssl_iostream_settings_string_offsets); i++) {
		const size_t offset = ssl_iostream_settings_string_offsets[i];
		const char **str1 = PTR_OFFSET(&set1_nonstr, offset);
		const char **str2 = PTR_OFFSET(&set2_nonstr, offset);

		if (null_strcmp(*str1, *str2) != 0)
			return FALSE;

		/* clear away the string pointer from the settings struct */
		*str1 = NULL;
		*str2 = NULL;
	}
	/* The set*_nonstr no longer have any pointers, so we can compare them
	   directly. */
	return memcmp(&set1_nonstr, &set2_nonstr, sizeof(set1_nonstr)) == 0;
}

void ssl_iostream_settings_drop_stream_only(struct ssl_iostream_settings *set)
{
	set->verbose = FALSE;
	set->verbose_invalid_cert = FALSE;
	set->allow_invalid_cert = FALSE;
}

const char *ssl_iostream_get_cipher(struct ssl_iostream *ssl_io,
				    unsigned int *bits_r)
{
	return ssl_vfuncs->get_cipher(ssl_io, bits_r);
}

const char *ssl_iostream_get_pfs(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_pfs(ssl_io);
}

const char *ssl_iostream_get_protocol_name(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_protocol_name(ssl_io);
}
