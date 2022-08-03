#ifndef IMAP_URLAUTH_WORKER_CLIENT_H
#define IMAP_URLAUTH_WORKER_CLIENT_H

#include "imap-urlauth-worker-common.h"

struct imap_urlauth_worker_client *
imap_urlauth_worker_client_init(struct client *client);
void imap_urlauth_worker_client_deinit(
	struct imap_urlauth_worker_client **_wclient);

int imap_urlauth_worker_client_connect(
	struct imap_urlauth_worker_client *wclient);
void imap_urlauth_worker_client_disconnect(
	struct imap_urlauth_worker_client *wclient);

#endif
