#ifndef COMMANDS_H
#define COMMANDS_H

struct client;

int cmd_lhlo(struct client *client, const char *args);
int cmd_mail(struct client *client, const char *args);
int cmd_rcpt(struct client *client, const char *args);
int cmd_quit(struct client *client, const char *args);
int cmd_vrfy(struct client *client, const char *args);
int cmd_rset(struct client *client, const char *args);
int cmd_noop(struct client *client, const char *args);
int cmd_data(struct client *client, const char *args);

#endif
