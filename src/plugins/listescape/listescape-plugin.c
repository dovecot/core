/* Copyright (c) 2007-2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "module-context.h"
#include "mail-storage-private.h"
#include "mailbox-list-private.h"
#include "listescape-plugin.h"

#include <stdlib.h>
#include <ctype.h>

#define DEFAULT_ESCAPE_CHAR '\\'

#define LIST_ESCAPE_LIST_CONTEXT(obj) \
	MODULE_CONTEXT(obj, listescape_list_module)

struct listescape_mailbox_list {
	union mailbox_list_module_context module_ctx;
	char escape_char;
};

const char *listescape_plugin_version = DOVECOT_VERSION;

static MODULE_CONTEXT_DEFINE_INIT(listescape_list_module,
				  &mailbox_list_module_register);

static const char *
list_escape(struct listescape_mailbox_list *mlist,
	    struct mail_namespace *ns, const char *str)
{
	char ns_sep = mail_namespace_get_sep(ns);
	char list_sep = mailbox_list_get_hierarchy_sep(ns->list);
	string_t *esc = t_str_new(64);
	unsigned int i;

	for (i = 0; str[i] != '\0'; i++) {
		if (str[i] == '*' || str[i] == '%')
			break;
	}
	if (i > ns->prefix_len)
		i = ns->prefix_len;

	if (i > 0 && strncmp(ns->prefix, str, i) == 0) {
		str_append_n(esc, str, i);
		str += i;
	}

	if (*str == '~') {
		str_printfa(esc, "%c%02x", mlist->escape_char, *str);
		str++;
	}
	for (; *str != '\0'; str++) {
		if (*str == ns_sep)
			str_append_c(esc, *str);
		else if (*str == list_sep ||
			 *str == mlist->escape_char || *str == '/')
			str_printfa(esc, "%c%02x", mlist->escape_char, *str);
		else
			str_append_c(esc, *str);
	}
	return str_c(esc);
}

static const char *
list_unescape(struct listescape_mailbox_list *mlist,
	      struct mail_namespace *ns, const char *str)
{
	char ns_sep = mail_namespace_get_sep(ns);
	char list_sep = mailbox_list_get_hierarchy_sep(ns->list);
	string_t *dest = t_str_new(strlen(str));
	unsigned int num;

	for (; *str != '\0'; str++) {
		if (*str == mlist->escape_char &&
		    i_isxdigit(str[1]) && i_isxdigit(str[2])) {
			if (str[1] >= '0' && str[1] <= '9')
				num = str[1] - '0';
			else
				num = i_toupper(str[1]) - 'A' + 10;
			num *= 16;
			if (str[2] >= '0' && str[2] <= '9')
				num += str[2] - '0';
			else
				num += i_toupper(str[2]) - 'A' + 10;

			str_append_c(dest, num);
			str += 2;
		} else if (*str == list_sep)
			str_append_c(dest, ns_sep);
		else
			str_append_c(dest, *str);
	}
	return str_c(dest);
}

static const char *listescape_list_get_vname(struct mailbox_list *list,
					     const char *storage_name)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);
	const char *vname;

	vname = mlist->module_ctx.super.get_vname(list, storage_name);
	return list_unescape(mlist, list->ns, vname);
}

static const char *listescape_list_get_storage_name(struct mailbox_list *list,
						    const char *vname)
{
	struct listescape_mailbox_list *mlist = LIST_ESCAPE_LIST_CONTEXT(list);

	return mlist->module_ctx.super.
		get_storage_name(list, list_escape(mlist, list->ns, vname));
}

static void listescape_mailbox_list_created(struct mailbox_list *list)
{
	struct mailbox_list_vfuncs *v = list->vlast;
	struct listescape_mailbox_list *mlist;
	const char *env;
	char ns_sep = mail_namespace_get_sep(list->ns);
	char list_sep = mailbox_list_get_hierarchy_sep(list);

	if (list_sep == ns_sep)
		return;

	mlist = p_new(list->pool, struct listescape_mailbox_list, 1);
	mlist->module_ctx.super = *v;
	list->vlast = &mlist->module_ctx.super;
	v->get_vname = listescape_list_get_vname;
	v->get_storage_name = listescape_list_get_storage_name;

	env = mail_user_plugin_getenv(list->ns->user, "listescape_char");
	mlist->escape_char = env != NULL && *env != '\0' ?
		env[0] : DEFAULT_ESCAPE_CHAR;

	MODULE_CONTEXT_SET(list, listescape_list_module, mlist);
}

static struct mail_storage_hooks listescape_mail_storage_hooks = {
	.mailbox_list_created = listescape_mailbox_list_created
};

void listescape_plugin_init(struct module *module)
{
	mail_storage_hooks_add(module, &listescape_mail_storage_hooks);
}

void listescape_plugin_deinit(void)
{
	mail_storage_hooks_remove(&listescape_mail_storage_hooks);
}
