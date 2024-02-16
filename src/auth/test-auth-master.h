#ifndef TEST_AUTH_MASTER_H
#define TEST_AUTH_MASTER_H 1

void auth_master_server_connected(int *server_fd, const char *socket);
void auth_master_server_deinit(void);

#endif
