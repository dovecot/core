#ifndef MAIL_SERVER_CONNECTION_H
#define MAIL_SERVER_CONNECTION_H

struct mail_server_connection *mail_server_connection_create(int fd);
void mail_server_connection_destroy(struct mail_server_connection **conn);

#endif
