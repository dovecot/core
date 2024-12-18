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
	const struct ssl_iostream_settings *ssl_set;
	const char *error;

	/* must be called after master_service_init_finish() so that if
	   initialization fails we can close the SSL listeners */
	i_assert(service->listeners != NULL || service->socket_count == 0);

	if (ssl_server_settings_get(service->event, &set, &server_set,
				    &error) < 0) {
		e_error(service->event, "%s - disabling SSL", error);
		master_service_ssl_io_listeners_remove(service);
		return;
	}
	if (strcmp(server_set->ssl, "no") == 0) {
		/* SSL disabled, don't use it */
		settings_free(set);
		settings_free(server_set);
		return;
	}

	ssl_server_settings_to_iostream_set(set, server_set, &ssl_set);
	if (ssl_iostream_server_context_cache_get(ssl_set, &service->ssl_ctx,
						  &error) < 0) {
		e_error(service->event,
			"SSL context initialization failed, disabling SSL: %s",
			error);
		master_service_ssl_io_listeners_remove(service);
	}
	settings_free(set);
	settings_free(server_set);
	settings_free(ssl_set);
}

void master_service_ssl_ctx_deinit(struct master_service *service)
{
	if (service->ssl_ctx != NULL)
		ssl_iostream_context_unref(&service->ssl_ctx);
}
