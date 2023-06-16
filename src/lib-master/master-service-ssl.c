/* Copyright (c) 2013-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "iostream-ssl.h"
#include "settings.h"
#include "master-service-private.h"
#include "master-service-ssl.h"

bool master_service_ssl_is_enabled(struct master_service *service)
{
	return service->ssl_ctx != NULL;
}

void master_service_ssl_ctx_init(struct master_service *service)
{
	const struct ssl_settings *set = NULL;
	const struct ssl_server_settings *server_set;
	struct ssl_iostream_settings ssl_set;
	const char *error;

	if (service->ssl_ctx_initialized)
		return;
	service->ssl_ctx_initialized = TRUE;

	/* must be called after master_service_init_finish() so that if
	   initialization fails we can close the SSL listeners */
	i_assert(service->listeners != NULL || service->socket_count == 0);

	if (settings_get(service->event, &ssl_setting_parser_info, 0,
			 &set, &error) < 0 ||
	    settings_get(service->event, &ssl_server_setting_parser_info, 0,
			 &server_set, &error) < 0) {
		e_error(service->event, "%s - disabling SSL", error);
		settings_free(set);
		master_service_ssl_io_listeners_remove(service);
		return;
	}
	if (strcmp(server_set->ssl, "no") == 0) {
		/* SSL disabled, don't use it */
		settings_free(set);
		settings_free(server_set);
		return;
	}

	i_zero(&ssl_set);
	ssl_set.pool = set->pool;
	pool_add_external_ref(ssl_set.pool, server_set->pool);
	ssl_set.min_protocol = set->ssl_min_protocol;
	ssl_set.cipher_list = set->ssl_cipher_list;
	ssl_set.curve_list = set->ssl_curve_list;
	ssl_set.ca = server_set->ssl_ca;
	ssl_set.cert.cert = server_set->ssl_cert;
	ssl_set.cert.key = server_set->ssl_key;
	ssl_set.dh = server_set->ssl_dh;
	ssl_set.cert.key_password = server_set->ssl_key_password;
	ssl_set.cert_username_field = server_set->ssl_cert_username_field;
	if (server_set->ssl_alt_cert != NULL &&
	    *server_set->ssl_alt_cert != '\0') {
		ssl_set.alt_cert.cert = server_set->ssl_alt_cert;
		ssl_set.alt_cert.key = server_set->ssl_alt_key;
		ssl_set.alt_cert.key_password = server_set->ssl_key_password;
	}
	ssl_set.crypto_device = set->ssl_crypto_device;
	ssl_set.skip_crl_check = !server_set->ssl_require_crl;

	ssl_set.verify_remote_cert = server_set->ssl_request_client_cert;
	ssl_set.prefer_server_ciphers = server_set->ssl_prefer_server_ciphers;
	ssl_set.compression = set->parsed_opts.compression;

	if (ssl_iostream_context_init_server(&ssl_set, &service->ssl_ctx,
					     &error) < 0) {
		e_error(service->event,
			"SSL context initialization failed, disabling SSL: %s",
			error);
		master_service_ssl_io_listeners_remove(service);
	}
	settings_free(set);
	settings_free(server_set);
}

void master_service_ssl_ctx_deinit(struct master_service *service)
{
	if (service->ssl_ctx != NULL)
		ssl_iostream_context_unref(&service->ssl_ctx);
	service->ssl_ctx_initialized = FALSE;
}
