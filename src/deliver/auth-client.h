#ifndef AUTH_CLIENT_H
#define AUTH_CLIENT_H

int auth_client_lookup_and_restrict(struct ioloop *ioloop,
				    const char *auth_socket,
				    const char *user, uid_t euid,
				    ARRAY_TYPE(string) *extra_fields_r);

#endif
