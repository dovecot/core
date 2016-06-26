#ifndef MASTER_CLIENT_H
#define MASTER_CLIENT_H

void master_client_connected(struct service_list *service_list);

void master_clients_init(void);
void master_clients_deinit(void);

#endif
