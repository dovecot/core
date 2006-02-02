/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "convert-storage.h"
#include "convert-plugin.h"

#include <stdlib.h>

void convert_plugin_init(void)
{
	const char *convert_mail, *mail, *home, *user;

	convert_mail = getenv("CONVERT_MAIL");
	if (convert_mail == NULL)
		return;

	mail = getenv("MAIL");
	if (mail == NULL)
		i_fatal("convert plugin: MAIL unset");
	user = getenv("USER");
	if (mail == NULL)
		i_fatal("convert plugin: USER unset");
	home = getenv("HOME");
	if (mail == NULL)
		i_fatal("convert plugin: HOME unset");

	if (convert_storage(user, home, convert_mail, mail) < 0)
		exit(FATAL_DEFAULT);
}

void convert_plugin_deinit(void)
{
}
