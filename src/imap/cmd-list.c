/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "strescape.h"
#include "imap-quote.h"
#include "imap-match.h"
#include "commands.h"

static const char *mailbox_flags2str(enum mailbox_flags flags, int listext)
{
	const char *str;

	if (flags & MAILBOX_PLACEHOLDER) {
		i_assert((flags & ~MAILBOX_CHILDREN) == MAILBOX_PLACEHOLDER);

		if (!listext)
			flags = MAILBOX_NOSELECT;
		flags |= MAILBOX_CHILDREN;
	}
	if ((flags & MAILBOX_NONEXISTENT) != 0 && !listext)
		flags |= MAILBOX_NOSELECT;

	str = t_strconcat((flags & MAILBOX_NOSELECT) ? " \\Noselect" : "",
			  (flags & MAILBOX_NONEXISTENT) ? " \\NonExistent" : "",
			  (flags & MAILBOX_PLACEHOLDER) ? " \\PlaceHolder" : "",
			  (flags & MAILBOX_CHILDREN) ? " \\Children" : "",
			  (flags & MAILBOX_NOCHILDREN) ? " \\NoChildren" : "",
			  (flags & MAILBOX_NOINFERIORS) ? " \\NoInferiors" : "",
			  (flags & MAILBOX_MARKED) ? " \\Marked" : "",
			  (flags & MAILBOX_UNMARKED) ? " \\UnMarked" : "",
			  NULL);

	return *str == '\0' ? "" : str+1;
}

static int mailbox_list(struct client *client, const char *mask,
			const char *sep, const char *reply,
			enum mailbox_list_flags list_flags, int listext)
{
	struct mailbox_list_context *ctx;
	struct mailbox_list *list;
	string_t *str;

	ctx = client->storage->list_mailbox_init(client->storage, mask,
						 list_flags);
	if (ctx == NULL)
		return FALSE;

	str = t_str_new(256);
	while ((list = client->storage->list_mailbox_next(ctx)) != NULL) {
		str_truncate(str, 0);
		str_printfa(str, "* %s (%s) \"%s\" ", reply,
			    mailbox_flags2str(list->flags, listext),
			    sep);
		if (strcasecmp(list->name, "INBOX") == 0)
			str_append(str, "INBOX");
		else
			imap_quote_append_string(str, list->name, FALSE);
		client_send_line(client, str_c(str));
	}

	return client->storage->list_mailbox_deinit(ctx);
}

static int parse_list_flags(struct client *client, struct imap_arg *args,
			    enum mailbox_list_flags *list_flags)
{
	const char *atom;

	while (args->type != IMAP_ARG_EOL) {
		if (args->type != IMAP_ARG_ATOM) {
			client_send_command_error(client,
				"List options contains non-atoms.");
			return FALSE;
		}

		atom = IMAP_ARG_STR(args);

		if (strcasecmp(atom, "SUBSCRIBED") == 0)
			*list_flags |= MAILBOX_LIST_SUBSCRIBED;
		else if (strcasecmp(atom, "CHILDREN") == 0)
			*list_flags |= MAILBOX_LIST_CHILDREN;
		else {
			client_send_tagline(client, t_strconcat(
				"BAD Invalid list option ", atom, NULL));
			return FALSE;
		}
		args++;
	}
	return TRUE;
}

int _cmd_list_full(struct client *client, int lsub)
{
	struct imap_arg *args;
        enum mailbox_list_flags list_flags;
	const char *ref, *mask;
	char sep_chr, sep[3];
	int failed, listext;

	sep_chr = client->storage->hierarchy_sep;
	if (IS_ESCAPED_CHAR(sep_chr)) {
		sep[0] = '\\';
		sep[1] = sep_chr;
		sep[2] = '\0';
	} else {
		sep[0] = sep_chr;
		sep[1] = '\0';
	}

	/* [(<options>)] <reference> <mailbox wildcards> */
	if (!client_read_args(client, 0, 0, &args))
		return FALSE;

	listext = FALSE;
	if (lsub)
		list_flags = MAILBOX_LIST_SUBSCRIBED | MAILBOX_LIST_FAST_FLAGS;
	else {
		list_flags = 0;
		if (args[0].type == IMAP_ARG_LIST) {
			listext = TRUE;
			if (!parse_list_flags(client,
					      IMAP_ARG_LIST(&args[0])->args,
					      &list_flags))
				return TRUE;
			args++;
		}
	}

	ref = imap_arg_string(&args[0]);
	mask = imap_arg_string(&args[1]);

	if (ref == NULL || mask == NULL) {
		client_send_command_error(client, "Invalid arguments.");
		return TRUE;
	}

	if (*mask == '\0' && !lsub) {
		/* special request to return the hierarchy delimiter */
		client_send_line(client, t_strconcat(
			"* LIST (\\Noselect) \"", sep, "\" \"\"", NULL));
		failed = FALSE;
	} else {
		if (*ref != '\0') {
			/* join reference + mask */
			if (*mask == sep_chr &&
			    ref[strlen(ref)-1] == sep_chr) {
				/* LIST A. .B -> A.B */
				mask++;
			}
			if (*mask != sep_chr &&
			    ref[strlen(ref)-1] != sep_chr) {
				/* LIST A B -> A.B */
				mask = t_strconcat(ref, sep, mask, NULL);
			} else {
				mask = t_strconcat(ref, mask, NULL);
			}
		}

		failed = !mailbox_list(client, mask, sep,
				       lsub ? "LSUB" : "LIST",
				       list_flags, listext);
	}

	if (failed)
		client_send_storage_error(client);
	else {
		client_send_tagline(client, lsub ?
				    "OK Lsub completed." :
				    "OK List completed.");
	}
	return TRUE;
}

int cmd_list(struct client *client)
{
	return _cmd_list_full(client, FALSE);
}
