/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "convert-storage.h"
#include "convert-plugin.h"

#include <stdlib.h>

const char *convert_plugin_version = PACKAGE_VERSION;

void convert_plugin_init(void)
{
	const char *convert_mail, *mail, *home, *user;
	bool skip_broken_mailboxes;

	convert_mail = getenv("CONVERT_MAIL");
	if (convert_mail == NULL)
		return;

	skip_broken_mailboxes = getenv("CONVERT_SKIP_BROKEN_MAILBOXES") != NULL;

	mail = getenv("MAIL");
	if (mail == NULL)
		i_fatal("convert plugin: MAIL unset");
	user = getenv("USER");
	if (mail == NULL)
		i_fatal("convert plugin: USER unset");
	home = getenv("HOME");
	if (mail == NULL)
		i_fatal("convert plugin: HOME unset");

	if (convert_storage(user, home, convert_mail, mail,
			    skip_broken_mailboxes) < 0)
		exit(FATAL_DEFAULT);
}

void convert_plugin_deinit(void)
{
}
