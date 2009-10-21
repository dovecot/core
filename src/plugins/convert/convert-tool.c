/* Copyright (c) 2006-2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"
#include "master-service.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-service.h"
#include "convert-storage.h"

#include <stdlib.h>
#include <unistd.h>

#define USAGE_STRING \
"Usage: <username> <home dir> <source mail env> <dest mail env>\n" \
"       [skip_broken_mailboxes] [skip_dotdirs] [alt_hierarchy_char=<c>]"

int main(int argc, char *argv[])
{
	struct mail_storage_service_input input;
	struct mail_user *user;
	struct convert_plugin_settings set;
	struct mail_namespace *dest_ns;
	struct mail_namespace_settings ns_set;
	const char *error;
	int i, ret = 0;

	master_service = master_service_init("convert-tool",
					     MASTER_SERVICE_FLAG_STANDALONE,
					     argc, argv, NULL);

	if (master_getopt(master_service) > 0)
		i_fatal(USAGE_STRING);
	if (argc - optind < 4)
		i_fatal(USAGE_STRING);

	env_put(t_strconcat("HOME=", argv[optind+1], NULL));

	memset(&set, 0, sizeof(set));
	for (i = optind + 4; i < argc; i++) {
		if (strcmp(argv[i], "skip_broken_mailboxes") == 0)
			set.skip_broken_mailboxes = TRUE;
		else if (strcmp(argv[i], "skip_dotdirs") == 0)
			set.skip_dotdirs = TRUE;
		else if (strncmp(argv[i], "alt_hierarchy_char=", 19) == 0)
			set.alt_hierarchy_char = argv[i][19];
		else
			i_fatal(USAGE_STRING);
	}

	memset(&input, 0, sizeof(input));
	input.username = argv[optind];

	master_service_init_log(master_service,
		t_strdup_printf("convert-tool(%s): ", input.username));
	user = mail_storage_service_init_user(master_service, &input, NULL, 0);

	memset(&ns_set, 0, sizeof(ns_set));
	ns_set.location = argv[4];

	dest_ns = mail_namespaces_init_empty(user);
	dest_ns->set = &ns_set;

	if (mail_storage_create(dest_ns, NULL, 0, &error) < 0) {
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
	mail_storage_service_deinit_user();
	master_service_deinit(&master_service);
	return ret <= 0 ? 1 : 0;
}
