#ifndef MASTER_SERVICE_SSL_H
#define MASTER_SERVICE_SSL_H

struct master_service;

bool master_service_ssl_is_enabled(struct master_service *service);

void master_service_ssl_ctx_init(struct master_service *service);
void master_service_ssl_ctx_deinit(struct master_service *service);

#endif
