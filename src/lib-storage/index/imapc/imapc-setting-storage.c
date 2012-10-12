/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "imapc-storage.h"
#include "imapc-settings.h"

struct mail_storage imapc_stub_storage = {
	.name = IMAPC_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_NO_ROOT,

	.v = {
		imapc_get_setting_parser_info,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL,
		NULL
	}
};
