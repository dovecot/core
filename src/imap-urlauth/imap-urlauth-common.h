#ifndef IMAP_URLAUTH_COMMON_H
#define IMAP_URLAUTH_COMMON_H

#include "lib.h"
#include "imap-urlauth-client.h"
#include "imap-urlauth-settings.h"

#define IMAP_URLAUTH_SOCKET "imap-urlauth"

#define IMAP_URLAUTH_PROTOCOL_MAJOR_VERSION 1
#define IMAP_URLAUTH_PROTOCOL_MINOR_VERSION 0

extern bool verbose_proctitle;
extern struct mail_storage_service_ctx *storage_service;

void imap_urlauth_refresh_proctitle(void);

#endif
