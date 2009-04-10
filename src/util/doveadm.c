/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "env-util.h"
#include "master-service.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-settings.h"
#include "mail-storage-service.h"

#include <stdlib.h>

static struct mail_user *mail_user;

static void ATTR_NORETURN
usage(void)
{
	i_fatal("usage: doveadm purge <user>\n");
}

static int cmd_purge(struct mail_user *user)
{
	struct mail_namespace *ns;
	int ret = 0;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->type == NAMESPACE_PRIVATE && ns->alias_for == NULL) {
			if (mail_storage_purge(ns->storage) < 0)
				ret = -1;
		}
	}
	return ret;
}

int main(int argc, char *argv[])
{
	enum mail_storage_service_flags service_flags = 0;
	struct master_service *service;
	const char *getopt_str, *user;
	int c, ret = 0;

	service = master_service_init("doveadm", MASTER_SERVICE_FLAG_STANDALONE,
				      argc, argv);

	user = getenv("USER");
	getopt_str = t_strconcat("u:v", master_service_getopt_string(), NULL);
	while ((c = getopt(argc, argv, getopt_str)) > 0) {
		switch (c) {
		case 'u':
			user = optarg;
			service_flags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;
			break;
		case 'v':
			service_flags |= MAIL_STORAGE_SERVICE_FLAG_DEBUG;
			break;
		default:
			if (!master_service_parse_option(service, c, optarg))
				usage();
		}
	}
	if (optind == argc)
		usage();

	if (user == NULL)
		i_fatal("USER environment is missing and -u option not used");

	mail_user = mail_storage_service_init_user(service, user, NULL,
						   service_flags);
	i_set_failure_prefix(t_strdup_printf("doveadm(%s): ",
					     mail_user->username));

	if (strcmp(argv[optind], "purge") == 0)
		ret = cmd_purge(mail_user);
	else
		usage();

	mail_user_unref(&mail_user);
	mail_storage_service_deinit_user();
	master_service_deinit(&service);
	return ret < 0 ? 1 : 0;
}
