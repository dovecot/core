#ifndef SUBMISSION_PROXY_H
#define SUBMISSION_PROXY_H

void submission_proxy_reset(struct client *client);
int submission_proxy_parse_line(struct client *client, const char *line);

void submission_proxy_error(struct client *client, const char *text);
const char *submission_proxy_get_state(struct client *client);

#endif
