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
	i_fatal(
"usage: doveadm \n"
"  purge <user>\n"
"  force-resync <user> <mailbox>\n"
);
}

static void cmd_purge(struct mail_user *user)
{
	struct mail_namespace *ns;

	for (ns = user->namespaces; ns != NULL; ns = ns->next) {
		if (ns->type != NAMESPACE_PRIVATE || ns->alias_for != NULL)
			continue;

		if (mail_storage_purge(ns->storage) < 0) {
			i_error("Purging namespace '%s' failed: %s", ns->prefix,
				mail_storage_get_last_error(ns->storage, NULL));
		}
	}
}

static struct mailbox *
mailbox_find_and_open(struct mail_user *user, const char *mailbox)
{
	struct mail_namespace *ns;
	struct mail_storage *storage;
	struct mailbox *box;
	const char *orig_mailbox = mailbox;

	ns = mail_namespace_find(user->namespaces, &mailbox);
	if (ns == NULL)
		i_fatal("Can't find namespace for mailbox %s", mailbox);

	storage = ns->storage;
	box = mailbox_open(&storage, mailbox, NULL, MAILBOX_OPEN_KEEP_RECENT |
			   MAILBOX_OPEN_IGNORE_ACLS);
	if (box == NULL) {
		i_fatal("Opening mailbox %s failed: %s", orig_mailbox,
			mail_storage_get_last_error(storage, NULL));
	}
	return box;
}

static void cmd_force_resync(struct mail_user *user, const char *mailbox)
{
	struct mail_storage *storage;
	struct mailbox *box;

	if (mailbox == NULL)
		usage();

	box = mailbox_find_and_open(user, mailbox);
	storage = mailbox_get_storage(box);
	if (mailbox_sync(box, MAILBOX_SYNC_FLAG_FORCE_RESYNC |
			 MAILBOX_SYNC_FLAG_FIX_INCONSISTENT, 0, NULL) < 0) {
		i_fatal("Forcing a resync on mailbox %s failed: %s", mailbox,
			mail_storage_get_last_error(storage, NULL));
	}
	mailbox_close(&box);
}

int main(int argc, char *argv[])
{
	enum mail_storage_service_flags service_flags = 0;
	struct master_service *service;
	const char *getopt_str, *user;
	int c;

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
		cmd_purge(mail_user);
	else if (strcmp(argv[optind], "force-resync") == 0)
		cmd_force_resync(mail_user, argv[optind+2]);
	else
		usage();

	mail_user_unref(&mail_user);
	mail_storage_service_deinit_user();
	master_service_deinit(&service);
	return 0;
}
