/* Copyright (c) 2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "buffer.h"
#include "iostream-ssl.h"
#include "master-service-private.h"
#include "master-service-settings.h"
#include "master-service-ssl-settings.h"
#include "master-service-ssl.h"

#include <unistd.h>

/* Check every 30 minutes if parameters file has been updated */
#define SSL_PARAMS_CHECK_INTERVAL (60*30)

#define SSL_PARAMETERS_PATH "ssl-params"

static int ssl_refresh_parameters(struct master_service *service)
{
#define BUF_APPEND_SIZE 1024
	const char *path;
	buffer_t *buf;
	void *data;
	ssize_t ret;
	int fd;

	if (ioloop_time == 0 ||
	    service->ssl_params_last_refresh > ioloop_time - SSL_PARAMS_CHECK_INTERVAL)
		return 0;
	service->ssl_params_last_refresh = ioloop_time;

	path = t_strdup_printf("%s/"SSL_PARAMETERS_PATH, service->set->base_dir);
	fd = net_connect_unix(path);
	if (fd == -1) {
		i_error("connect(%s) failed: %m", path);
		return -1;
	}
	net_set_nonblock(fd, FALSE);

	buf = buffer_create_dynamic(default_pool, BUF_APPEND_SIZE*2);
	for (;;) {
		data = buffer_append_space_unsafe(buf, BUF_APPEND_SIZE);
		ret = read(fd, data, BUF_APPEND_SIZE);
		buffer_set_used_size(buf, buf->used - BUF_APPEND_SIZE +
				     (ret < 0 ? 0 : ret));
		if (ret <= 0)
			break;
	}
	if (ret < 0)
		i_error("read(%s) failed: %m", path);
	else if (ssl_iostream_context_import_params(service->ssl_ctx, buf) < 0) {
		i_error("Corrupted SSL parameters file in state_dir: "
			"ssl-parameters.dat - disabling SSL %u", (int)buf->used);
		ret = -1;
	}
	i_close_fd(&fd);
	buffer_free(&buf);
	return ret < 0 ? -1 : 0;
}

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

	(void)ssl_refresh_parameters(service);

	set = master_service_ssl_settings_get(service);

	memset(&ssl_set, 0, sizeof(ssl_set));
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

	memset(&ssl_set, 0, sizeof(ssl_set));
	ssl_set.protocols = set->ssl_protocols;
	ssl_set.cipher_list = set->ssl_cipher_list;
	ssl_set.ca = set->ssl_ca;
	ssl_set.cert = set->ssl_cert;
	ssl_set.key = set->ssl_key;
	ssl_set.key_password = set->ssl_key_password;
	ssl_set.cert_username_field = set->ssl_cert_username_field;
	ssl_set.crypto_device = set->ssl_crypto_device;

	ssl_set.verbose = set->verbose_ssl;
	ssl_set.verify_remote_cert = set->ssl_verify_client_cert;

	if (ssl_iostream_context_init_server(&ssl_set, &service->ssl_ctx,
					     &error) < 0) {
		i_error("SSL context initialization failed, disabling SSL: %s",
			error);
		master_service_ssl_io_listeners_remove(service);
		return;
	}
	if (ssl_refresh_parameters(service) < 0) {
		i_error("Couldn't initialize SSL parameters, disabling SSL");
		ssl_iostream_context_deinit(&service->ssl_ctx);
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
