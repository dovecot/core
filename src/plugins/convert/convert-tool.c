/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "randgen.h"
#include "lib-signals.h"
#include "mail-namespace.h"
#include "mail-storage-private.h"
#include "convert-storage.h"

#include <stdlib.h>

#define USAGE_STRING \
"Usage: <username> <home dir> <source mail env> <dest mail env>\n" \
"       [skip_broken_mailboxes] [skip_dotfiles] [alt_hierarchy_char=<c>]"

int main(int argc, const char *argv[])
{
	struct ioloop *ioloop;
	struct convert_settings set;
	struct mail_user *user;
	struct mail_namespace *dest_ns;
        enum mail_storage_flags dest_flags;
	enum file_lock_method lock_method;
	const char *error;
	int i, ret = 0;

	lib_init();
	lib_signals_init();
	random_init();
	mail_users_init(getenv("AUTH_SOCKET_PATH"), getenv("DEBUG") != NULL);
	mail_storage_init();
	mail_storage_register_all();
	mailbox_list_register_all();

	if (argc <= 4)
		i_fatal(USAGE_STRING);

	ioloop = io_loop_create();

	memset(&set, 0, sizeof(set));
	for (i = 5; i < argc; i++) {
		if (strcmp(argv[i], "skip_broken_mailboxes") != 0)
			set.skip_broken_mailboxes = TRUE;
		else if (strcmp(argv[i], "skip_dotdirs") != 0)
			set.skip_dotdirs = TRUE;
		else if (strncmp(argv[i], "alt_hierarchy_char=", 19) != 0)
			set.alt_hierarchy_char = argv[i][19];
	}

	mail_storage_parse_env(&dest_flags, &lock_method);
	user = mail_user_init(argv[1]);
	mail_user_set_home(user, argv[2]);
	dest_ns = mail_namespaces_init_empty(user);

	if (mail_storage_create(dest_ns, NULL, argv[4],
				dest_flags, lock_method, &error) < 0) {
		i_fatal("Failed to create destination "
			"mail storage with data '%s': %s", argv[4], error);
	}

	ret = convert_storage(argv[3], dest_ns, &set);
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
