#ifndef IMAP_HIBERNATE_CLIENT_H
#define IMAP_HIBERNATE_CLIENT_H

void imap_hibernate_client_create(int fd, bool debug);

void imap_hibernate_clients_init(void);
void imap_hibernate_clients_deinit(void);

#endif
