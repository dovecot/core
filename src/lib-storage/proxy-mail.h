#ifndef __PROXY_MAIL_H
#define __PROXY_MAIL_H

#include "mail-storage.h"

struct proxy_mail {
	struct mail proxy_mail;
	struct mail *mail;
};

void proxy_mail_init(struct proxy_mail *proxy, struct mail *mail);
void proxy_mail_next(struct proxy_mail *proxy);

#endif
