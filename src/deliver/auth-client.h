#ifndef AUTH_CLIENT_H
#define AUTH_CLIENT_H

int auth_client_lookup_and_restrict(const char *auth_socket, bool debug,
				    const char **user, uid_t euid, pool_t pool,
				    ARRAY_TYPE(const_string) *extra_fields_r);

#endif
