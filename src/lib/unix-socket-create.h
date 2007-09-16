#ifndef UNIX_SOCKET_CREATE_H
#define UNIX_SOCKET_CREATE_H

int unix_socket_create(const char *path, int mode,
		       uid_t uid, gid_t gid, int backlog);

#endif
