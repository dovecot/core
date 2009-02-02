/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "randgen.h"
#include "lib-signals.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "convert-settings.h"
#include "convert-storage.h"

#include <stdlib.h>

#define USAGE_STRING \
"Usage: <username> <home dir> <source mail env> <dest mail env>\n" \
"       [skip_broken_mailboxes] [skip_dotfiles] [alt_hierarchy_char=<c>]"

int main(int argc, const char *argv[])
{
	struct ioloop *ioloop;
	struct mail_user *user;
	const struct convert_settings *set;
	const struct mail_user_settings *user_set;
	const struct mail_storage_settings *mail_set;
	struct convert_plugin_settings set2;
	struct mail_namespace *dest_ns;
	struct mail_namespace_settings ns_set;
	const char *error;
	int i, ret = 0;

	lib_init();
	lib_signals_init();
	random_init();
	mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	convert_settings_read(&set, &user_set);
	mail_set = mail_user_set_get_driver_settings(user_set, "MAIL");
	mail_users_init(set->auth_socket_path, mail_set->mail_debug);

	if (argc <= 4)
		i_fatal(USAGE_STRING);

	ioloop = io_loop_create();

	memset(&set2, 0, sizeof(set2));
	for (i = 5; i < argc; i++) {
		if (strcmp(argv[i], "skip_broken_mailboxes") != 0)
			set2.skip_broken_mailboxes = TRUE;
		else if (strcmp(argv[i], "skip_dotdirs") != 0)
			set2.skip_dotdirs = TRUE;
		else if (strncmp(argv[i], "alt_hierarchy_char=", 19) != 0)
			set2.alt_hierarchy_char = argv[i][19];
	}

	user = mail_user_alloc(argv[1], user_set);
	mail_user_set_home(user, argv[2]);
	mail_user_set_vars(user, geteuid(), "convert", NULL, NULL);
	if (mail_user_init(user, &error) < 0)
		i_fatal("Mail user initialization failed: %s", error);

	memset(&ns_set, 0, sizeof(ns_set));
	ns_set.location = argv[4];

	dest_ns = mail_namespaces_init_empty(user);
	dest_ns->set = &ns_set;

	if (mail_storage_create(dest_ns, NULL, 0, &error) < 0) {
		i_fatal("Failed to create destination "
			"mail storage with data '%s': %s", argv[4], error);
	}

	ret = convert_storage(argv[3], dest_ns, &set2);
	if (ret > 0)
		i_info("Successfully converted");
	else if (ret == 0)
		i_error("Source storage not found");
	else
		i_error("Internal failure");
	mail_user_unref(&user);

	io_loop_destroy(&ioloop);
	mail_storage_deinit();
	mail_users_deinit();
	lib_signals_deinit();
	lib_deinit();
	return ret <= 0 ? 1 : 0;
}
