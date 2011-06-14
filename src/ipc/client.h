#ifndef CLIENT_H
#define CLIENT_H

struct client *client_create(int fd);
void client_destroy(struct client **client);

void clients_destroy_all(void);

#endif
