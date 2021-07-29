/* Copyright (c) 2009-2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "doveadm-protocol.h"

#include <sysexits.h>

static const struct exit_code_str {
	int code;
	const char *str;
} exit_code_strings[] = {
	{ DOVEADM_EX_UNKNOWN, "UNKNOWN" },
	{ EX_TEMPFAIL, "TEMPFAIL" },
	{ EX_USAGE, "USAGE" },
	{ EX_NOUSER, "NOUSER" },
	{ EX_NOPERM, "NOPERM" },
	{ EX_PROTOCOL, "PROTOCOL" },
	{ EX_DATAERR, "DATAERR" },
	{ DOVEADM_EX_NOREPLICATE, "NOREPLICATE" },
	{ DOVEADM_EX_REFERRAL, "REFERRAL" },
	{ DOVEADM_EX_NOTFOUND, "NOTFOUND" }
};

const char *doveadm_exit_code_to_str(int code)
{
	for(size_t i = 0; i < N_ELEMENTS(exit_code_strings); i++) {
		const struct exit_code_str *ptr = &exit_code_strings[i];
		if (ptr->code == code)
			return ptr->str;
	}
	return "UNKNOWN";
}

int doveadm_str_to_exit_code(const char *reason)
{
	for(size_t i = 0; i < N_ELEMENTS(exit_code_strings); i++) {
		const struct exit_code_str *ptr = &exit_code_strings[i];
		if (strcmp(ptr->str, reason) == 0)
			return ptr->code;
	}
	return DOVEADM_EX_UNKNOWN;
}

char doveadm_log_type_to_char(enum log_type type)
{
	switch(type) {
	case LOG_TYPE_DEBUG:
		return '\x01';
	case LOG_TYPE_INFO:
		return '\x02';
	case LOG_TYPE_WARNING:
		return '\x03';
	case LOG_TYPE_ERROR:
		return '\x04';
	case LOG_TYPE_FATAL:
		return '\x05';
	case LOG_TYPE_PANIC:
		return '\x06';
	default:
		i_unreached();
	}
}

bool doveadm_log_type_from_char(char c, enum log_type *type_r)
{
	switch(c) {
	case '\x01':
		*type_r = LOG_TYPE_DEBUG;
		break;
	case '\x02':
		*type_r = LOG_TYPE_INFO;
		break;
	case '\x03':
		*type_r = LOG_TYPE_WARNING;
		break;
	case '\x04':
		*type_r = LOG_TYPE_ERROR;
		break;
	case '\x05':
		*type_r = LOG_TYPE_FATAL;
		break;
	case '\x06':
		*type_r = LOG_TYPE_PANIC;
		break;
	default:
		*type_r = LOG_TYPE_WARNING;
		return FALSE;
	}
	return TRUE;
}
