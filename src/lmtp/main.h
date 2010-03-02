#ifndef MAIN_H
#define MAIN_H

extern const char *dns_client_socket_path;
extern struct mail_storage_service_ctx *storage_service;

void listener_client_destroyed(void);

#endif
