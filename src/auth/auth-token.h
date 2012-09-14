#ifndef AUTH_TOKEN_H
#define AUTH_TOKEN_H

void auth_token_init(void);
void auth_token_deinit(void);

const char *auth_token_get(const char *service, const char *session_pid,
			   const char *username, const char *session_id);

#endif

