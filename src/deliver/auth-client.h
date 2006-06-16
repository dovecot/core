#ifndef __AUTH_CLIENT_H
#define __AUTH_CLIENT_H

int auth_client_put_user_env(struct ioloop *ioloop, const char *auth_socket,
			     const char *user, uid_t euid);

#endif
