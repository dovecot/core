#ifndef IMAP_MASTER_CLIENT_H
#define IMAP_MASTER_CLIENT_H

void imap_master_client_create(int fd);

void imap_master_clients_init(void);
void imap_master_clients_deinit(void);

#endif
