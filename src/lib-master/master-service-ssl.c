/* Copyright (c) 2013-2017 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "iostream-ssl.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "master-service-ssl-settings.h"
#include "master-service-ssl.h"

#include <unistd.h>

int master_service_ssl_init(struct master_service *service,
			    struct istream **input, struct ostream **output,
			    struct ssl_iostream **ssl_iostream_r,
			    const char **error_r)
{
	const struct master_service_ssl_settings *set;
	struct ssl_iostream_settings ssl_set;

	i_assert(service->ssl_ctx_initialized);

	if (service->ssl_ctx == NULL) {
		*error_r = "Failed to initialize SSL context";
		return -1;
	}

	set = master_service_ssl_settings_get(service);

	i_zero(&ssl_set);
	ssl_set.verbose = set->verbose_ssl;
	ssl_set.verify_remote_cert = set->ssl_verify_client_cert;
	return io_stream_create_ssl_server(service->ssl_ctx, &ssl_set,
					   input, output, ssl_iostream_r, error_r);
}

bool master_service_ssl_is_enabled(struct master_service *service)
{
	return service->ssl_ctx != NULL;
}

void master_service_ssl_ctx_init(struct master_service *service)
{
	const struct master_service_ssl_settings *set;
	struct ssl_iostream_settings ssl_set;
	const char *error;

	if (service->ssl_ctx_initialized)
		return;
	service->ssl_ctx_initialized = TRUE;

	/* must be called after master_service_init_finish() so that if
	   initialization fails we can close the SSL listeners */
	i_assert(service->listeners != NULL || service->socket_count == 0);

	set = master_service_ssl_settings_get(service);
	if (strcmp(set->ssl, "no") == 0) {
		/* SSL disabled, don't use it */
		return;
	}

	i_zero(&ssl_set);
	ssl_set.protocols = set->ssl_protocols;
	ssl_set.cipher_list = set->ssl_cipher_list;
	ssl_set.ca = set->ssl_ca;
	ssl_set.cert = set->ssl_cert;
	ssl_set.key = set->ssl_key;
	ssl_set.dh = set->ssl_dh;
	ssl_set.key_password = set->ssl_key_password;
	ssl_set.cert_username_field = set->ssl_cert_username_field;
	ssl_set.crypto_device = set->ssl_crypto_device;

	ssl_set.verbose = set->verbose_ssl;
	ssl_set.verify_remote_cert = set->ssl_verify_client_cert;
	ssl_set.prefer_server_ciphers = set->ssl_prefer_server_ciphers;
	ssl_set.compression = set->parsed_opts.compression;

	if (ssl_iostream_context_init_server(&ssl_set, &service->ssl_ctx,
					     &error) < 0) {
		i_error("SSL context initialization failed, disabling SSL: %s",
			error);
		master_service_ssl_io_listeners_remove(service);
		return;
	}
}

void master_service_ssl_ctx_deinit(struct master_service *service)
{
	if (service->ssl_ctx != NULL)
		ssl_iostream_context_deinit(&service->ssl_ctx);
	service->ssl_ctx_initialized = FALSE;
}
