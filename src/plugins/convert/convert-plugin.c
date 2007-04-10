/* Copyright (C) 2006 Timo Sirainen */

#include "lib.h"
#include "convert-storage.h"
#include "convert-plugin.h"

#include <stdlib.h>

const char *convert_plugin_version = PACKAGE_VERSION;

void convert_plugin_init(void)
{
	const char *convert_mail, *mail, *str;
	struct convert_settings set;

	convert_mail = getenv("CONVERT_MAIL");
	if (convert_mail == NULL)
		return;

	mail = getenv("MAIL");
	if (mail == NULL)
		i_fatal("convert plugin: MAIL unset");

	memset(&set, 0, sizeof(set));
	set.user = getenv("USER");
	if (set.user == NULL)
		i_fatal("convert plugin: USER unset");
	set.home = getenv("HOME");
	if (set.home == NULL)
		i_fatal("convert plugin: HOME unset");

	set.skip_broken_mailboxes = getenv("CONVERT_SKIP_BROKEN_MAILBOXES") != NULL;
	set.skip_dotfiles = getenv("CONVERT_SKIP_DOTFILES") != NULL;

	str = getenv("CONVERT_ALT_HIERARCHY_CHAR");
	set.alt_hierarchy_char = *str != '\0' ? *str : '_';

	if (convert_storage(convert_mail, mail, &set) < 0)
		exit(FATAL_DEFAULT);
}

void convert_plugin_deinit(void)
{
}
