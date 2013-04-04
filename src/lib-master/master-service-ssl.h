#ifndef MASTER_SERVICE_SSL_H
#define MASTER_SERVICE_SSL_H

struct ssl_iostream;

int master_service_ssl_init(struct master_service *service,
			    struct istream **input, struct ostream **output,
			    struct ssl_iostream **ssl_iostream_r,
			    const char **error_r);

bool master_service_ssl_is_enabled(struct master_service *service);

void master_service_ssl_ctx_init(struct master_service *service);
void master_service_ssl_ctx_deinit(struct master_service *service);

#endif
