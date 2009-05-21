/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "env-util.h"
#include "master-service.h"
#include "mail-user.h"
#include "mail-namespace.h"
#include "mail-storage.h"
#include "mail-storage-settings.h"
#include "mail-storage-service.h"

#include <stdio.h>
#include <stdlib.h>

static struct mail_user *mail_user;
static int killed_signo = 0;

static void ATTR_NORETURN
usage(void)
{
	i_fatal(
"usage: doveadm \n"
"  purge <user>\n"
"  force-resync <user> <mailbox>\n"
);
}

static void sig_die(const siginfo_t *si, void *context ATTR_UNUSED)
{
	killed_signo = si->si_signo;
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

static void handle_command(struct mail_user *mail_user, const char *cmd,
			   char *args[])
{
	if (strcmp(cmd, "purge") == 0)
		cmd_purge(mail_user);
	else if (strcmp(cmd, "force-resync") == 0)
		cmd_force_resync(mail_user, args[0]);
	else
		usage();
}

static void
handle_single_user(struct master_service *service, const char *username,
		   enum mail_storage_service_flags service_flags, char *argv[])
{
	struct mail_storage_service_input input;

	if (username == NULL)
		i_fatal("USER environment is missing and -u option not used");

	memset(&input, 0, sizeof(input));
	input.username = username;
	mail_user = mail_storage_service_init_user(service, &input, NULL,
						   service_flags);
	handle_command(mail_user, argv[0], argv+1);
	mail_user_unref(&mail_user);
	mail_storage_service_deinit_user();
}

static int
handle_next_user(struct mail_storage_service_multi_ctx *multi,
		 const struct mail_storage_service_input *input,
		 pool_t pool, char *argv[])
{
	struct mail_storage_service_multi_user *multi_user;
	const char *error;
	int ret;

	i_set_failure_prefix(t_strdup_printf("doveadm(%s): ", input->username));
	ret = mail_storage_service_multi_lookup(multi, input, pool,
						&multi_user, &error);
	if (ret <= 0) {
		if (ret == 0) {
			i_info("User no longer exists, skipping");
			return 0;
		} else {
			i_error("User lookup failed: %s", error);
			return -1;
		}
	}
	if (mail_storage_service_multi_next(multi, multi_user,
					    &mail_user, &error) < 0) {
		i_error("User init failed: %s", error);
		mail_storage_service_multi_user_free(multi_user);
		return -1;
	}
	mail_storage_service_multi_user_free(multi_user);
	handle_command(mail_user, argv[0], argv+1);
	mail_user_unref(&mail_user);
	return 0;
}

static void
handle_all_users(struct master_service *service,
		 enum mail_storage_service_flags service_flags, char *argv[])
{
	struct mail_storage_service_input input;
	struct mail_storage_service_multi_ctx *multi;
	unsigned int user_idx, user_count, interval, n;
	const char *user;
	pool_t pool;
	int ret;

	service_flags |= MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP;

	memset(&input, 0, sizeof(input));

	multi = mail_storage_service_multi_init(service, NULL, service_flags);
	pool = pool_alloconly_create("multi user", 8192);

        lib_signals_set_handler(SIGINT, FALSE, sig_die, NULL);
	lib_signals_set_handler(SIGTERM, FALSE, sig_die, NULL);

	user_count = mail_storage_service_multi_all_init(multi);
	n = user_count / 10000;
	for (interval = 10; n > 0 && interval < 1000; interval *= 10)
		n /= 10;
	
	user_idx = 0;
	while ((ret = mail_storage_service_multi_all_next(multi, &user)) > 0) {
		p_clear(pool);
		input.username = user;
		T_BEGIN {
			ret = handle_next_user(multi, &input, pool, argv);
		} T_END;
		if (ret < 0)
			break;
		if ((service_flags & MAIL_STORAGE_SERVICE_FLAG_DEBUG) != 0) {
			if (++user_idx % interval == 0) {
				printf("\r%d / %d", user_idx, user_count);
				fflush(stdout);
			}
		}
		if (killed_signo != 0) {
			i_warning("Killed with signal %d", killed_signo);
			ret = -1;
			break;
		}
	}
	if ((service_flags & MAIL_STORAGE_SERVICE_FLAG_DEBUG) != 0)
		printf("\n");
	i_set_failure_prefix("doveadm: ");
	if (ret < 0)
		i_error("Failed to iterate through some users");
	mail_storage_service_multi_deinit(&multi);
	pool_unref(&pool);
}

int main(int argc, char *argv[])
{
	enum mail_storage_service_flags service_flags = 0;
	struct master_service *service;
	const char *getopt_str, *username;
	bool all_users = FALSE;
	int c;

	service = master_service_init("doveadm", MASTER_SERVICE_FLAG_STANDALONE,
				      argc, argv);

	username = getenv("USER");
	getopt_str = t_strconcat("au:v", master_service_getopt_string(), NULL);
	while ((c = getopt(argc, argv, getopt_str)) > 0) {
		switch (c) {
		case 'a':
			all_users = TRUE;
			break;
		case 'u':
			username = optarg;
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

	if (!all_users) {
		handle_single_user(service, username, service_flags,
				   argv + optind);
	} else {
		handle_all_users(service, service_flags, argv + optind);
	}
	master_service_deinit(&service);
	return 0;
}
