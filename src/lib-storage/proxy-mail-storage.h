#ifndef __PROXY_MAIL_STORAGE_H
#define __PROXY_MAIL_STORAGE_H

#include "mail-storage.h"

struct proxy_mail_storage {
	struct mail_storage proxy_storage;
	struct mail_storage *storage;
};

void proxy_mail_storage_init(struct proxy_mail_storage *proxy,
			     struct mail_storage *storage);

#endif
