#ifndef CLIENT_AUTHENTICATE_H
#define CLIENT_AUTHENTICATE_H

struct imap_arg;

#define IMAP_AUTH_FAILED_MSG \
	"["IMAP_RESP_CODE_AUTHFAILED"] "AUTH_FAILED_MSG
#define IMAP_AUTHZ_FAILED_MSG \
	"["IMAP_RESP_CODE_AUTHZFAILED"] Authorization failed"

const char *client_authenticate_get_capabilities(struct imap_client *client);

int cmd_login(struct imap_client *client, const struct imap_arg *args);
int cmd_authenticate(struct imap_client *client, const struct imap_arg *args);

#endif
