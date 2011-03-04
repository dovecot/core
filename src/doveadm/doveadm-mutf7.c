/* Copyright (c) 2009-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "imap-utf7.h"
#include "doveadm.h"

#include <stdio.h>
#include <unistd.h>

static void cmd_mailbox_mutf7(int argc, char *argv[])
{
	string_t *str;
	bool from_utf8;
	unsigned int i;
	int c;

	from_utf8 = TRUE;
	while ((c = getopt(argc, argv, "78")) > 0) {
		switch (c) {
		case '7':
			from_utf8 = FALSE;
			break;
		case '8':
			from_utf8 = TRUE;
			break;
		default:
			help(&doveadm_cmd_mailbox_mutf7);
		}
	}
	argv += optind;

	if (argv[0] == NULL)
		help(&doveadm_cmd_mailbox_mutf7);

	str = t_str_new(128);
	for (i = 0; argv[i] != NULL; i++) {
		str_truncate(str, 0);
		if (from_utf8) {
			if (imap_utf8_to_utf7(argv[i], str) < 0) {
				i_error("Mailbox name not valid UTF-8: %s",
					argv[i]);
			}
		} else {
			if (imap_utf7_to_utf8(argv[i], str) < 0) {
				i_error("Mailbox name not valid mUTF-7: %s",
					argv[i]);
			}
		}
		printf("%s\n", str_c(str));
	}
}

struct doveadm_cmd doveadm_cmd_mailbox_mutf7 = {
	cmd_mailbox_mutf7, "mailbox mutf7",
	"[-7|-8] <name> [...]"
};
