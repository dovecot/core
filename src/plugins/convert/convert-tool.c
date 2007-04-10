/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "randgen.h"
#include "lib-signals.h"
#include "mail-storage.h"
#include "convert-storage.h"

#include <stdlib.h>

#define USAGE_STRING \
"Usage: <username> <home dir> <source mail env> <dest mail env>\n" \
"       [skip_broken_mailboxes] [skip_dotfiles] [alt_hierarchy_char=<c>]"

int main(int argc, const char *argv[])
{
	struct ioloop *ioloop;
	struct convert_settings set;
	int i, ret = 0;

	lib_init();
	lib_signals_init();
	random_init();
	mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	if (argc <= 4)
		i_fatal(USAGE_STRING);

	ioloop = io_loop_create();

	memset(&set, 0, sizeof(set));
	set.user = argv[1];
	set.home = argv[2];

	for (i = 5; i < argc; i++) {
		if (strcmp(argv[i], "skip_broken_mailboxes") != 0)
			set.skip_broken_mailboxes = TRUE;
		else if (strcmp(argv[i], "skip_dotfiles") != 0)
			set.skip_dotfiles = TRUE;
		else if (strncmp(argv[i], "alt_hierarchy_char=", 19) != 0)
			set.alt_hierarchy_char = argv[i][19];
	}

	ret = convert_storage(argv[3], argv[4], &set);
	if (ret > 0)
		i_info("Successfully converted");
	else if (ret == 0)
		i_error("Source storage not found");
	else
		i_error("Internal failure");

	io_loop_destroy(&ioloop);
	mail_storage_deinit();
	lib_signals_deinit();
	lib_deinit();
	return ret;
}
