#ifndef SUBMISSION_PROXY_H
#define SUBMISSION_PROXY_H

void submission_proxy_reset(struct client *client);
int submission_proxy_parse_line(struct client *client, const char *line);

void submission_proxy_failed(struct client *client,
			     enum login_proxy_failure_type type,
			     const char *reason, bool reconnecting);
const char *submission_proxy_get_state(struct client *client);

#endif
