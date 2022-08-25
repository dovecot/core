/* Copyright (c) 2009-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-utf7.h"
#include "doveadm.h"

#include <stdio.h>
#include <unistd.h>

static void cmd_mailbox_mutf7(struct doveadm_cmd_context *cctx)
{
	string_t *str;
	const char *const *names;
	bool from_utf8, to_utf8;
	unsigned int i;

	if (!doveadm_cmd_param_array(cctx, "name", &names))
		help_ver2(&doveadm_cmd_mailbox_mutf7);
	if (!doveadm_cmd_param_bool(cctx, "from-utf8", &from_utf8)) {
		if (!doveadm_cmd_param_bool(cctx, "to-utf8", &to_utf8))
			from_utf8 = TRUE;
		else
			from_utf8 = !to_utf8;
	}

	str = t_str_new(128);
	for (i = 0; names[i] != NULL; i++) {
		str_truncate(str, 0);
		if (from_utf8) {
			if (imap_utf8_to_utf7(names[i], str) < 0) {
				e_error(cctx->event,
					"Mailbox name not valid UTF-8: %s",
					names[i]);
				doveadm_exit_code = EX_DATAERR;
			}
		} else {
			if (imap_utf7_to_utf8(names[i], str) < 0) {
				e_error(cctx->event,
					"Mailbox name not valid mUTF-7: %s",
					names[i]);
				doveadm_exit_code = EX_DATAERR;
			}
		}
		printf("%s\n", str_c(str));
	}
}

struct doveadm_cmd_ver2 doveadm_cmd_mailbox_mutf7 = {
	.name = "mailbox mutf7",
	.cmd = cmd_mailbox_mutf7,
	.usage = "[-7|-8] <name> [...]",
DOVEADM_CMD_PARAMS_START
DOVEADM_CMD_PARAM('7', "to-utf8", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('8', "from-utf8", CMD_PARAM_BOOL, 0)
DOVEADM_CMD_PARAM('\0', "name", CMD_PARAM_ARRAY, CMD_PARAM_FLAG_POSITIONAL)
DOVEADM_CMD_PARAMS_END
};
