/* Copyright (c) 2003-2017 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "imap-utf7.h"
#include "imap-quote.h"
#include "imap-commands.h"
#include "mail-namespace.h"

struct namespace_order {
	int secondary_order;
	struct mail_namespace *ns;
};

static int namespace_order_cmp(const struct namespace_order *no1,
			       const struct namespace_order *no2)
{
	if (no1->ns->set->order < no2->ns->set->order)
		return -1;
	if (no1->ns->set->order > no2->ns->set->order)
		return 1;

	if (no1->secondary_order < no2->secondary_order)
		return -1;
	if (no1->secondary_order > no2->secondary_order)
		return 1;
	return 0;
}

static void list_namespaces(struct mail_namespace *ns,
			    enum mail_namespace_type type, string_t *str)
{
	ARRAY(struct namespace_order) ns_order;
	struct namespace_order *no;
	unsigned int count = 0;
	string_t *mutf7_prefix;
	char ns_sep;

	t_array_init(&ns_order, 4);

	while (ns != NULL) {
		if (ns->type == type &&
		    (ns->flags & NAMESPACE_FLAG_HIDDEN) == 0) {
			no = array_append_space(&ns_order);
			no->ns = ns;
			no->secondary_order = ++count;
		}
		ns = ns->next;
	}

	if (array_count(&ns_order) == 0) {
		str_append(str, "NIL");
		return;
	}
	array_sort(&ns_order, namespace_order_cmp);

	mutf7_prefix = t_str_new(64);
	str_append_c(str, '(');
	array_foreach_modifiable(&ns_order, no) {
		ns_sep = mail_namespace_get_sep(no->ns);
		str_append_c(str, '(');

		str_truncate(mutf7_prefix, 0);
		if (imap_utf8_to_utf7(no->ns->prefix, mutf7_prefix) < 0) {
			i_panic("LIST: Namespace prefix not UTF-8: %s",
				no->ns->prefix);
		}

		imap_append_string(str, str_c(mutf7_prefix));
		str_append(str, " \"");
		if (ns_sep == '\\')
			str_append_c(str, '\\');
		str_append_c(str, ns_sep);
		str_append(str, "\")");
	}
	str_append_c(str, ')');
}

bool cmd_namespace(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	string_t *str;

	str = t_str_new(256);
	str_append(str, "* NAMESPACE ");

	list_namespaces(client->user->namespaces,
			MAIL_NAMESPACE_TYPE_PRIVATE, str);
	str_append_c(str, ' ');
	list_namespaces(client->user->namespaces,
			MAIL_NAMESPACE_TYPE_SHARED, str);
	str_append_c(str, ' ');
	list_namespaces(client->user->namespaces,
			MAIL_NAMESPACE_TYPE_PUBLIC, str);

	client_send_line(client, str_c(str));
	client_send_tagline(cmd, "OK Namespace completed.");
	return TRUE;
}
