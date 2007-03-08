/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "randgen.h"
#include "lib-signals.h"
#include "mail-storage.h"
#include "convert-storage.h"

#include <stdlib.h>

int main(int argc, const char *argv[])
{
	struct ioloop *ioloop;
	int ret = 0;

	lib_init();
	lib_signals_init();
	random_init();
	mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	if (argc <= 4) {
		i_fatal("Usage: <username> <home dir> "
			"<source mail env> <dest mail env> "
			"[<1=skip broken mailboxes>]");
	}

	ioloop = io_loop_create();

	ret = convert_storage(argv[1], argv[2], argv[3], argv[4],
			      argv[5] != NULL && atoi(argv[5]) == 1);
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
