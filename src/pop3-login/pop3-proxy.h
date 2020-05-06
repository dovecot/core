#ifndef POP3_PROXY_H
#define POP3_PROXY_H

void pop3_proxy_reset(struct client *client);
int pop3_proxy_parse_line(struct client *client, const char *line);

void pop3_proxy_failed(struct client *client,
		       enum login_proxy_failure_type type,
		       const char *reason, bool reconnecting);
const char *pop3_proxy_get_state(struct client *client);

#endif
