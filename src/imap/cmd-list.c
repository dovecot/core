/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "str.h"
#include "strescape.h"
#include "imap-quote.h"
#include "imap-match.h"
#include "commands.h"
#include "namespace.h"

enum {
	_MAILBOX_LIST_HIDE_CHILDREN	= 0x1000000,
	_MAILBOX_LIST_LISTEXT		= 0x0800000
};

static const char *
mailbox_flags2str(enum mailbox_flags flags, enum mailbox_list_flags list_flags)
{
	const char *str;

	if (flags & MAILBOX_PLACEHOLDER) {
		i_assert((flags & ~MAILBOX_CHILDREN) == MAILBOX_PLACEHOLDER);

		if ((list_flags & _MAILBOX_LIST_LISTEXT) == 0)
			flags = MAILBOX_NOSELECT;
		flags |= MAILBOX_CHILDREN;
	}
	if ((flags & MAILBOX_NONEXISTENT) != 0 &&
	    (list_flags & _MAILBOX_LIST_LISTEXT) == 0) {
		flags |= MAILBOX_NOSELECT;
		flags &= ~MAILBOX_NONEXISTENT;
	}

	if ((list_flags & _MAILBOX_LIST_HIDE_CHILDREN) != 0)
		flags &= ~(MAILBOX_CHILDREN|MAILBOX_NOCHILDREN);

	str = t_strconcat(
		(flags & MAILBOX_NOSELECT) ? " \\Noselect" : "",
		(flags & MAILBOX_NONEXISTENT) ? " \\NonExistent" : "",
		(flags & MAILBOX_PLACEHOLDER) ? " \\PlaceHolder" : "",
		(flags & MAILBOX_CHILDREN) ? " \\HasChildren" : "",
		(flags & MAILBOX_NOCHILDREN) ? " \\HasNoChildren" : "",
		(flags & MAILBOX_NOINFERIORS) ? " \\NoInferiors" : "",
		(flags & MAILBOX_MARKED) ? " \\Marked" : "",
		(flags & MAILBOX_UNMARKED) ? " \\UnMarked" : "",
		NULL);

	return *str == '\0' ? "" : str+1;
}

static int mailbox_list(struct client *client, struct mail_storage *storage,
			const char *mask, const char *sep, const char *reply,
			enum mailbox_list_flags list_flags)
{
	struct mailbox_list_context *ctx;
	struct mailbox_list *list;
	string_t *str;

	ctx = storage->list_mailbox_init(storage, mask, list_flags);
	if (ctx == NULL)
		return FALSE;

	str = t_str_new(256);
	while ((list = storage->list_mailbox_next(ctx)) != NULL) {
		str_truncate(str, 0);
		str_printfa(str, "* %s (%s) \"%s\" ", reply,
			    mailbox_flags2str(list->flags, list_flags),
			    sep);
		if (strcasecmp(list->name, "INBOX") == 0)
			str_append(str, "INBOX");
		else
			imap_quote_append_string(str, list->name, FALSE);
		client_send_line(client, str_c(str));
	}

	return storage->list_mailbox_deinit(ctx);
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
	struct namespace *ns;
	struct mail_storage *storage;
	struct imap_arg *args;
        enum mailbox_list_flags list_flags;
	const char *ref, *mask;
	char sep_chr, sep[3];
	int failed;

	/* [(<options>)] <reference> <mailbox wildcards> */
	if (!client_read_args(client, 0, 0, &args))
		return FALSE;

	if (lsub) {
		/* LSUB - we don't care about flags */
		list_flags = MAILBOX_LIST_SUBSCRIBED | MAILBOX_LIST_FAST_FLAGS |
			_MAILBOX_LIST_HIDE_CHILDREN;
	} else if (args[0].type != IMAP_ARG_LIST) {
		/* LIST - allow children flags, but don't require them */
		list_flags = 0;
	} else {
		list_flags = _MAILBOX_LIST_LISTEXT;
		if (!parse_list_flags(client, IMAP_ARG_LIST(&args[0])->args,
				      &list_flags))
			return TRUE;
		args++;

		/* don't show children flags unless explicitly specified */
		if ((list_flags & MAILBOX_LIST_CHILDREN) == 0)
			list_flags |= _MAILBOX_LIST_HIDE_CHILDREN;
	}

	ref = imap_arg_string(&args[0]);
	mask = imap_arg_string(&args[1]);

	if (ref == NULL || mask == NULL) {
		client_send_command_error(client, "Invalid arguments.");
		return TRUE;
	}

	/* FIXME: really needs some work.. */
	ns = namespace_find(client->namespaces, *ref != '\0' ? ref : mask);
	if (ns != NULL)
		storage = ns->storage;
	else
		storage = client->namespaces->storage;

	sep_chr = storage->hierarchy_sep;
	if (sep_chr == '"' || sep_chr == '\\') {
		sep[0] = '\\';
		sep[1] = sep_chr;
		sep[2] = '\0';
	} else {
		sep[0] = sep_chr;
		sep[1] = '\0';
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

		failed = !mailbox_list(client, storage, mask, sep,
				       lsub ? "LSUB" : "LIST", list_flags);
	}

	if (failed)
		client_send_storage_error(client, storage);
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
