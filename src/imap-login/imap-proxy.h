#ifndef IMAP_PROXY_H
#define IMAP_PROXY_H

void imap_proxy_reset(struct client *client);
int imap_proxy_parse_line(struct client *client, const char *line);

void imap_proxy_failed(struct client *client,
		       enum login_proxy_failure_type type,
		       const char *reason, bool reconnecting);
const char *imap_proxy_get_state(struct client *client);

#endif
