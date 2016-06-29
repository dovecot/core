#ifndef AUTH_POLICY_H
#define AUTH_POLICY_H

typedef void (*auth_policy_callback_t)(int, void *);

void auth_policy_check(struct auth_request *request, const char *password, auth_policy_callback_t cb, void *context);
void auth_policy_report(struct auth_request *request);
void auth_policy_init(void);
void auth_policy_deinit(void);

#endif
