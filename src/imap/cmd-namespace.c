/* Copyright (C) 2003 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "imap-quote.h"
#include "commands.h"
#include "namespace.h"

static void list_namespaces(struct namespace *ns, enum namespace_type type,
			    string_t *str)
{
	int found = FALSE;

	while (ns != NULL) {
		if (ns->type == type) {
			if (!found) {
				str_append_c(str, '(');
				found = TRUE;
			}
			str_append_c(str, '(');
			imap_quote_append_string(str, ns->prefix, FALSE);
			str_append(str, " \"");
			if (ns->hierarchy_sep == '"' ||
			    ns->hierarchy_sep == '\\')
				str_append_c(str, '\\');
			str_append_c(str, ns->hierarchy_sep);
			str_append(str, "\")");
		}

		ns = ns->next;
	}

	if (found)
		str_append_c(str, ')');
	else
		str_append(str, "NIL");
}

int cmd_namespace(struct client *client)
{
	string_t *str;

	str = t_str_new(256);
	str_append(str, "* NAMESPACE ");

        list_namespaces(client->namespaces, NAMESPACE_PRIVATE, str);
	str_append_c(str, ' ');
	list_namespaces(client->namespaces, NAMESPACE_SHARED, str);
	str_append_c(str, ' ');
        list_namespaces(client->namespaces, NAMESPACE_PUBLIC, str);

	client_send_line(client, str_c(str));
	client_send_tagline(client, "OK Namespace completed.");
	return TRUE;
}
