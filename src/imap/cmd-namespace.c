/* Copyright (c) 2003-2011 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "imap-quote.h"
#include "imap-commands.h"
#include "mail-namespace.h"

static void list_namespaces(struct mail_namespace *ns,
			    enum namespace_type type, string_t *str)
{
	bool found = FALSE;

	while (ns != NULL) {
		if (ns->type == type &&
		    (ns->flags & NAMESPACE_FLAG_HIDDEN) == 0) {
			if (!found) {
				str_append_c(str, '(');
				found = TRUE;
			}
			str_append_c(str, '(');
			imap_quote_append_string(str, ns->prefix, FALSE);
			str_append(str, " \"");
			str_append(str, ns->sep_str);
			str_append(str, "\")");
		}

		ns = ns->next;
	}

	if (found)
		str_append_c(str, ')');
	else
		str_append(str, "NIL");
}

bool cmd_namespace(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	string_t *str;

	str = t_str_new(256);
	str_append(str, "* NAMESPACE ");

        list_namespaces(client->user->namespaces, NAMESPACE_PRIVATE, str);
	str_append_c(str, ' ');
	list_namespaces(client->user->namespaces, NAMESPACE_SHARED, str);
	str_append_c(str, ' ');
        list_namespaces(client->user->namespaces, NAMESPACE_PUBLIC, str);

	client_send_line(client, str_c(str));
	client_send_tagline(cmd, "OK Namespace completed.");
	return TRUE;
}
