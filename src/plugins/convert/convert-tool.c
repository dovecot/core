/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "ioloop.h"
#include "randgen.h"
#include "lib-signals.h"
#include "convert-storage.h"

/* ugly, but automake doesn't like having it built as both static and
   dynamic object.. */
#include "convert-storage.c"

int main(int argc, const char *argv[])
{
	struct ioloop *ioloop;
	int ret = 0;

	lib_init();
	lib_signals_init();
	random_init();
	mail_storage_init();
	mail_storage_register_all();

	if (argc <= 4) {
		i_fatal("Usage: <username> <home dir> "
			"<source mail env> <dest mail env>");
	}

	ioloop = io_loop_create(system_pool);

	ret = convert_storage(argv[1], argv[2], argv[3], argv[4]);
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
