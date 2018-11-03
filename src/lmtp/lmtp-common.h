#ifndef LMTP_COMMON_H
#define LMTP_COMMON_H

extern char *dns_client_socket_path, *base_dir;
extern struct mail_storage_service_ctx *storage_service;
extern struct anvil_client *anvil;

extern struct smtp_server *lmtp_server;

void lmtp_anvil_init(void);

void listener_client_destroyed(void);

#endif
