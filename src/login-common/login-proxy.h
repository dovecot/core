#ifndef __LOGIN_PROXY_H
#define __LOGIN_PROXY_H

/* Create a proxy to given host. Returns -1 if failed, or 0 if ok.
   In any case the client should be destroyed after this call. */
int login_proxy_new(struct client *client, const char *host,
		    unsigned int port, const char *login_cmd);

void login_proxy_deinit(void);

#endif
