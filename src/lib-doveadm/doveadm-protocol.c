/* Copyright (c) 2009-2021 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "doveadm-protocol.h"
#include "array.h"

#include <sysexits.h>
#include <stdio.h>

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
	{ DOVEADM_EX_CHANGED, "CHANGED" },
	{ DOVEADM_EX_REFERRAL, "REFERRAL" },
	{ DOVEADM_EX_NOTFOUND, "NOTFOUND" },
	{ DOVEADM_EX_EXPIRED, "EXPIRED" },
};

struct module_exit_code_str {
        const struct module* module;
	int code;
	const char *str;
};
static ARRAY(struct module_exit_code_str) module_exit_code_strings = ARRAY_INIT;

void doveadm_exit_code_deinit(void);
void doveadm_exit_code_deinit(void)
{
	/* allow calling this even if doveadm_exit_code_add() hasn't been called */
	if (array_is_created(&module_exit_code_strings)) {
		array_free(&module_exit_code_strings);
        }
}

void doveadm_exit_code_add(const struct module *module,
                           const int code, const char *str)
{
	const struct module_exit_code_str *module_exit_code;
	struct module_exit_code_str new_exit_code;

	if (!array_is_created(&module_exit_code_strings)) {
		i_array_init(&module_exit_code_strings, 16);
        }

	array_foreach(&module_exit_code_strings, module_exit_code) {
		if (module_exit_code->code == code) {
                        fprintf(stderr,
                                "Warning: doveadm exit code %d(%s) already "
                                "exists from plugin \"%s\", registration for "
                                "plugin \"%s\" will be ignored",
                                code, str,
                                module_exit_code->module->name,
                                module->name);
		}
		if (strcmp(module_exit_code->str, str) == 0) {
                        fprintf(stderr,
                                "Warning: doveadm exit code %s(%d) already "
                                "exists from plugin \"%s\", registration for "
                                "plugin \"%s\" will be ignored",
                                str, code,
                                module_exit_code->module->name,
                                module->name);
		}
	}

	i_zero(&new_exit_code);
	new_exit_code.module = module;
	new_exit_code.code = code;
        new_exit_code.str = str;

	array_push_back(&module_exit_code_strings, &new_exit_code);
}

void doveadm_exit_code_remove(const int code)
{
	const struct module_exit_code_str *module_exit_code;
	unsigned int idx = UINT_MAX;

	array_foreach(&module_exit_code_strings, module_exit_code) {
		if (module_exit_code->code == code) {
			idx = array_foreach_idx(&module_exit_code_strings,
                                                module_exit_code);
			break;
		}
	}
	i_assert(idx != UINT_MAX);

	array_delete(&module_exit_code_strings, idx, 1);
}

const char *doveadm_exit_code_to_str(int code)
{
        const struct module_exit_code_str *module_exit_code_str;
	array_foreach(&module_exit_code_strings, module_exit_code_str) {
                if (module_exit_code_str->code == code) {
                        return module_exit_code_str->str;
                }
	}
	for(size_t i = 0; i < N_ELEMENTS(exit_code_strings); i++) {
		const struct exit_code_str *ptr = &exit_code_strings[i];
		if (ptr->code == code)
			return ptr->str;
	}
	return "UNKNOWN";
}

int doveadm_str_to_exit_code(const char *reason)
{
        const struct module_exit_code_str *module_exit_code_str;
	array_foreach(&module_exit_code_strings, module_exit_code_str) {
                if (strcmp(module_exit_code_str->str, reason) == 0) {
                        return module_exit_code_str->code;
                }
	}
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
