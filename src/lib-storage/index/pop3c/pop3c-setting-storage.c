/* Copyright (c) 2012 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "pop3c-storage.h"
#include "pop3c-settings.h"

struct mail_storage pop3c_stub_storage = {
	.name = POP3C_STORAGE_NAME,
	.class_flags = MAIL_STORAGE_CLASS_FLAG_NO_ROOT,

	.v = {
		pop3c_get_setting_parser_info,
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
