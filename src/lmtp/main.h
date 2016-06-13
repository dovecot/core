#ifndef MAIN_H
#define MAIN_H

extern char *dns_client_socket_path, *base_dir;
extern struct mail_storage_service_ctx *storage_service;
extern struct anvil_client *anvil;

void listener_client_destroyed(void);

#endif
