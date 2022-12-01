#ifndef IMAP_URLAUTH_WORKER_CLIENT_H
#define IMAP_URLAUTH_WORKER_CLIENT_H

#include "imap-urlauth-worker-common.h"

int imap_urlauth_worker_client_connect(struct client *wclient);
void imap_urlauth_worker_client_disconnect(struct client *wclient);

#endif
