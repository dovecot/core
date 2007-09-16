/* Copyright (c) 2005-2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "mail-storage.h"
#include "mailbox-list-private.h"
#include "quota.h"
#include "quota-plugin.h"

#include <stdlib.h>

/* defined by imap, pop3, lda */
extern void (*hook_mail_storage_created)(struct mail_storage *storage);

void (*quota_next_hook_mail_storage_created)(struct mail_storage *storage);
void (*quota_next_hook_mailbox_list_created)(struct mailbox_list *list);

const char *quota_plugin_version = PACKAGE_VERSION;
struct quota *quota_set;

static void quota_root_add_rules(const char *root_name, 
				 struct quota_root *root)
{
	const char *rule_name, *rule, *error;
	unsigned int i;

	t_push();

	rule_name = t_strconcat(root_name, "_RULE", NULL);
	for (i = 2;; i++) {
		rule = getenv(rule_name);

		if (rule == NULL)
			break;

		if (quota_root_add_rule(root, rule, &error) < 0) {
			i_fatal("Quota root %s: Invalid rule: %s",
				root_name, rule);
		}
		rule_name = t_strdup_printf("%s_RULE%d", root_name, i);
	}

	t_pop();
}

static void quota_root_add_warning_rules(const char *root_name,
					 struct quota_root *root)
{
	const char *rule_name, *rule, *error;
	unsigned int i;

	t_push();

	rule_name = t_strconcat(root_name, "_WARNING", NULL);
	for (i = 2;; i++) {
		rule = getenv(rule_name);

		if (rule == NULL)
			break;

		if (quota_root_add_warning_rule(root, rule, &error) < 0) {
			i_fatal("Quota root %s: Invalid warning rule: %s",
				root_name, rule);
		}
		rule_name = t_strdup_printf("%s_WARNING%d", root_name, i);
	}

	t_pop();
}

void quota_plugin_init(void)
{
	struct quota_root *root;
	unsigned int i;
	const char *env;

	env = getenv("QUOTA");
	if (env == NULL)
		return;

	quota_set = quota_init();

	root = quota_root_init(quota_set, env);
	if (root == NULL)
		i_fatal("Couldn't create quota root: %s", env);
	quota_root_add_rules("QUOTA", root);
	quota_root_add_warning_rules("QUOTA", root);

	t_push();
	for (i = 2;; i++) {
		const char *root_name;

		root_name = t_strdup_printf("QUOTA%d", i);
		env = getenv(root_name);

		if (env == NULL)
			break;

		root = quota_root_init(quota_set, env);
		if (root == NULL)
			i_fatal("Couldn't create quota root: %s", env);
		quota_root_add_rules(root_name, root);
		quota_root_add_warning_rules(root_name, root);
	}
	t_pop();

	quota_next_hook_mail_storage_created = hook_mail_storage_created;
	hook_mail_storage_created = quota_mail_storage_created;

	quota_next_hook_mailbox_list_created = hook_mailbox_list_created;
	hook_mailbox_list_created = quota_mailbox_list_created;
}

void quota_plugin_deinit(void)
{
	if (quota_set != NULL) {
		hook_mail_storage_created =
			quota_next_hook_mail_storage_created;
		hook_mailbox_list_created =
			quota_next_hook_mailbox_list_created;
		quota_deinit(&quota_set);
	}
}
