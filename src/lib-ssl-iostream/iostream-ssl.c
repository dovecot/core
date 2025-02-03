/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "module-dir.h"
#include "settings.h"
#include "iostream-ssl-private.h"

static bool ssl_module_loaded = FALSE;
static struct module *ssl_module = NULL;
static const struct iostream_ssl_vfuncs *ssl_vfuncs = NULL;

static void ssl_module_unload(void)
{
	ssl_iostream_context_cache_free();
	module_dir_unload(&ssl_module);
}

void iostream_ssl_module_init(const struct iostream_ssl_vfuncs *vfuncs)
{
	ssl_vfuncs = vfuncs;
	ssl_module_loaded = TRUE;
}

int ssl_module_load(const char **error_r)
{
	const char *plugin_names[] = { "ssl_iostream_openssl", NULL };
	struct module_dir_load_settings mod_set;

	i_zero(&mod_set);
	mod_set.abi_version = DOVECOT_ABI_VERSION;
	mod_set.setting_name = "<built-in lib-ssl-iostream lookup>";
	mod_set.require_init_funcs = TRUE;
	if (module_dir_try_load_missing(&ssl_module, MODULE_DIR, plugin_names,
					&mod_set, error_r) < 0)
		return -1;
	module_dir_init(ssl_module);
	if (!ssl_module_loaded) {
		*error_r = t_strdup_printf(
			"%s didn't call iostream_ssl_module_init() - SSL not initialized",
			plugin_names[0]);
		module_dir_unload(&ssl_module);
		return -1;
	}

	/* Destroy SSL module after (most of) the others. Especially lib-fs
	   backends may still want to access SSL module in their own
	   atexit-callbacks. */
	lib_atexit_priority(ssl_module_unload, LIB_ATEXIT_PRIORITY_LOW);
	return 0;
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
	struct ssl_iostream_settings set_copy = *set;

	/* Allow client to provide an invalid certificate. The caller is
	   expected to check and handle it however it wants. */
	set_copy.allow_invalid_cert = TRUE;

	if (!ssl_module_loaded) {
		if (ssl_module_load(error_r) < 0)
			return -1;
	}
	if (io_stream_ssl_global_init(&set_copy, error_r) < 0)
		return -1;
	return ssl_vfuncs->context_init_server(&set_copy, ctx_r, error_r);
}

void ssl_iostream_context_ref(struct ssl_iostream_context *ctx)
{
	ssl_vfuncs->context_ref(ctx);
}

void ssl_iostream_context_unref(struct ssl_iostream_context **_ctx)
{
	struct ssl_iostream_context *ctx = *_ctx;

	if (*_ctx == NULL)
		return;
	*_ctx = NULL;
	ssl_vfuncs->context_unref(ctx);
}

int io_stream_create_ssl_client(struct ssl_iostream_context *ctx, const char *host,
				struct event *event_parent,
				enum ssl_iostream_flags flags,
				struct istream **input, struct ostream **output,
				struct ssl_iostream **iostream_r,
				const char **error_r)
{
	return ssl_vfuncs->create(ctx, event_parent, host, TRUE, flags,
				  input, output, iostream_r, error_r);
}

int io_stream_create_ssl_server(struct ssl_iostream_context *ctx,
				struct event *event_parent,
				struct istream **input, struct ostream **output,
				struct ssl_iostream **iostream_r,
				const char **error_r)
{
	return ssl_vfuncs->create(ctx, event_parent, NULL, TRUE, 0,
				  input, output, iostream_r, error_r);
}

int io_stream_autocreate_ssl_client(
	const struct ssl_iostream_client_autocreate_parameters *parameters,
	struct istream **input, struct ostream **output,
	struct ssl_iostream **iostream_r,
	const char **error_r)
{
	const struct ssl_settings *ssl_set;
	const struct ssl_iostream_settings *set;
	struct ssl_iostream_context *ctx;
	int ret;

	i_assert(parameters->event_parent != NULL);
	if (ssl_client_settings_get(parameters->event_parent,
				    &ssl_set, error_r) < 0)
		return -1;
	ssl_client_settings_to_iostream_set(ssl_set, &set);
	if ((parameters->flags & SSL_IOSTREAM_FLAG_DISABLE_CA_FILES) != 0) {
		pool_t pool = pool_alloconly_create("ssl iostream settings copy",
						    sizeof(*set));
		struct ssl_iostream_settings *set_copy =
			p_memdup(pool, set, sizeof(*set));
		set_copy->pool = pool;
		pool_add_external_ref(pool, set->pool);
		set_copy->ca_dir = NULL;
		settings_free(set);
		set = set_copy;
	}
	settings_free(ssl_set);

	ret = ssl_iostream_client_context_cache_get(set, &ctx, error_r);
	settings_free(set);
	if (ret < 0)
		return -1;
	if (ret > 0 && parameters->application_protocols != NULL) {
		ssl_iostream_context_set_application_protocols(ctx,
				parameters->application_protocols);
	}
	ret = io_stream_create_ssl_client(ctx, parameters->host,
					  parameters->event_parent,
					  parameters->flags, input,
					  output, iostream_r, error_r);
	ssl_iostream_context_unref(&ctx);
	return ret;
}

int io_stream_autocreate_ssl_server(
	const struct ssl_iostream_server_autocreate_parameters *parameters,
	struct istream **input, struct ostream **output,
	struct ssl_iostream **iostream_r,
	const char **error_r)
{
	const struct ssl_settings *ssl_set;
	const struct ssl_server_settings *ssl_server_set;
	const struct ssl_iostream_settings *set;
	struct ssl_iostream_context *ctx;
	int ret;

	i_assert(parameters->event_parent != NULL);
	if (ssl_server_settings_get(parameters->event_parent, &ssl_set,
				    &ssl_server_set, error_r) < 0)
		return -1;
	ssl_server_settings_to_iostream_set(ssl_set, ssl_server_set, &set);
	settings_free(ssl_set);
	settings_free(ssl_server_set);

	ret = ssl_iostream_server_context_cache_get(set, &ctx, error_r);
	settings_free(set);
	if (ret < 0)
		return -1;
	if (ret > 0 && parameters->application_protocols != NULL) {
		ssl_iostream_context_set_application_protocols(ctx,
				parameters->application_protocols);
	}
	ret = io_stream_create_ssl_server(ctx, parameters->event_parent, input,
					  output, iostream_r, error_r);
	ssl_iostream_context_unref(&ctx);
	return ret;
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

bool ssl_iostream_get_allow_invalid_cert(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_allow_invalid_cert(ssl_io);
}

const char *ssl_iostream_get_peer_username(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_peer_username(ssl_io);
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

static bool quick_strcmp(const char *str1, const char *str2)
{
	/* fast path: settings can point to the same strings */
	if (str1 == str2)
		return TRUE;
	return null_strcmp(str1, str2) == 0;
}

bool ssl_iostream_settings_equals(const struct ssl_iostream_settings *set1,
				  const struct ssl_iostream_settings *set2)
{
	if (set1 == set2)
		return TRUE;

	if (!quick_strcmp(set1->cert.cert.content, set2->cert.cert.content) ||
	    !quick_strcmp(set1->cert.key.content, set2->cert.key.content) ||
	    !quick_strcmp(set1->cert.key_password, set2->cert.key_password))
		return FALSE;

	if (!quick_strcmp(set1->alt_cert.cert.content,
			  set2->alt_cert.cert.content) ||
	    !quick_strcmp(set1->alt_cert.key.content,
			  set2->alt_cert.key.content) ||
	    !quick_strcmp(set1->alt_cert.key_password,
			  set2->alt_cert.key_password))
		return FALSE;

	if (!quick_strcmp(set1->ca.content, set2->ca.content) ||
	    !quick_strcmp(set1->ca_dir, set2->ca_dir))
		return FALSE;

	if (!quick_strcmp(set1->min_protocol, set2->min_protocol) ||
	    !quick_strcmp(set1->cipher_list, set2->cipher_list) ||
	    !quick_strcmp(set1->ciphersuites, set2->ciphersuites) ||
	    !quick_strcmp(set1->curve_list, set2->curve_list) ||
	    !quick_strcmp(set1->dh.content, set2->dh.content) ||
	    !quick_strcmp(set1->cert_username_field,
			  set2->cert_username_field) ||
	    !quick_strcmp(set1->crypto_device, set2->crypto_device))
		return FALSE;

	if (set1->skip_crl_check != set2->skip_crl_check ||
	    set1->verify_remote_cert != set2->verify_remote_cert ||
	    set1->allow_invalid_cert != set2->allow_invalid_cert ||
	    set1->prefer_server_ciphers != set2->prefer_server_ciphers ||
	    set1->compression != set2->compression ||
	    set1->tickets != set2->tickets)
		return FALSE;
	return TRUE;
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

enum ssl_iostream_protocol_version
ssl_iostream_get_protocol_version(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_protocol_version(ssl_io);
}

const char *ssl_iostream_get_ja3(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_ja3(ssl_io);
}

const char *ssl_iostream_get_application_protocol(struct ssl_iostream *ssl_io)
{
	return ssl_vfuncs->get_application_protocol(ssl_io);
}

void ssl_iostream_context_set_application_protocols(struct ssl_iostream_context *ssl_ctx,
						    const char *const *names)
{
	ssl_vfuncs->set_application_protocols(ssl_ctx, names);
}

int ssl_iostream_get_channel_binding(struct ssl_iostream *ssl_io,
				     const char *type, const buffer_t **data_r,
				     const char **error_r)
{
	*data_r = NULL;
	*error_r = NULL;

	if (ssl_io == NULL) {
		*error_r = "Channel binding not available for insecure channel";
		return -1;
	}
	if (ssl_vfuncs->get_channel_binding == NULL) {
		*error_r = "Channel binding not supported";
		return -1;
	}

	return ssl_vfuncs->get_channel_binding(ssl_io, type, data_r, error_r);
}
