#ifndef POP3_PROXY_H
#define POP3_PROXY_H

void pop3_proxy_reset(struct client *client);
int pop3_proxy_parse_line(struct client *client, const char *line);

#endif
