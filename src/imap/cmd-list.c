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

static int
list_namespace_mailboxes(struct client *client, struct imap_match_glob *glob,
			 struct namespace *ns, struct mailbox_list_context *ctx,
			 enum mailbox_list_flags list_flags)
{
	struct mailbox_list *list;
	const char *name;
	string_t *str, *name_str;
	int inbox_found = FALSE;

	t_push();
	str = t_str_new(256);
	name_str = t_str_new(256);
	while ((list = mail_storage_mailbox_list_next(ctx)) != NULL) {
		str_truncate(name_str, 0);
		str_append(name_str, ns->prefix);
		str_append(name_str, list->name);

		if (ns->sep != ns->real_sep) {
                        char *p = str_c_modifyable(name_str);
			for (; *p != '\0'; p++) {
				if (*p == ns->real_sep)
					*p = ns->sep;
			}
		}
		name = str_c(name_str);

		if (*ns->prefix != '\0') {
			/* With masks containing '*' we do the checks here
			   so prefix is included in matching */
			if (glob != NULL &&
			    imap_match(glob, name) != IMAP_MATCH_YES)
				continue;
		} else if (strcasecmp(list->name, "INBOX") == 0) {
			if (!ns->inbox)
				continue;

			name = "INBOX";
			inbox_found = TRUE;
		}

		str_truncate(str, 0);
		str_printfa(str, "* LIST (%s) \"%s\" ",
			    mailbox_flags2str(list->flags, list_flags),
			    ns->sep_str);
		imap_quote_append_string(str, name, FALSE);
		client_send_line(client, str_c(str));
	}
	t_pop();

	if (!inbox_found && ns->inbox) {
		/* INBOX always exists */
		str_printfa(str, "* LIST () \"%s\" \"INBOX\"", ns->sep_str);
		client_send_line(client, str_c(str));
	}

	return mail_storage_mailbox_list_deinit(ctx);
}

static void skip_prefix(const char **prefix, const char **mask, int inbox)
{
	size_t mask_len, prefix_len, len;

	prefix_len = strlen(*prefix);
	mask_len = strlen(*mask);
	len = I_MIN(prefix_len, mask_len);

	if (strncmp(*prefix, *mask, len) == 0 ||
	    (inbox && len >= 6 &&
	     strncasecmp(*prefix, *mask, 6) == 0)) {
		*prefix += len;
		*mask += len;
	}
}

static int list_mailboxes(struct client *client,
			  const char *ref, const char *mask,
			  enum mailbox_list_flags list_flags)
{
	struct namespace *ns;
	struct mailbox_list_context *ctx;
	struct imap_match_glob *glob;
	enum imap_match_result match;
	const char *cur_prefix, *cur_ref, *cur_mask;
	size_t len;
	int inbox;

	inbox = strncasecmp(ref, "INBOX", 5) == 0 ||
		(*ref == '\0' && strncasecmp(mask, "INBOX", 5) == 0);

	for (ns = client->namespaces; ns != NULL; ns = ns->next) {
		t_push();
		cur_prefix = ns->prefix;
		cur_ref = ref;
		cur_mask = mask;
		if (*ref != '\0') {
			skip_prefix(&cur_prefix, &cur_ref, inbox);

			if (*cur_ref != '\0' && *cur_prefix != '\0') {
				/* reference parameter didn't match with
				   namespace prefix. skip this. */
				t_pop();
				continue;
			}
		}

		if (*cur_ref == '\0' && *cur_prefix != '\0') {
			skip_prefix(&cur_prefix, &cur_mask,
				    inbox && cur_ref == ref);
		}

		glob = imap_match_init(pool_datastack_create(), mask,
				       inbox && cur_ref == ref, ns->sep);

		if (*cur_ref != '\0' || *cur_prefix == '\0')
			match = IMAP_MATCH_CHILDREN;
		else {
			len = strlen(cur_prefix);
			if (cur_prefix[len-1] == ns->sep)
				cur_prefix = t_strndup(cur_prefix, len-1);
			match = ns->hidden ? IMAP_MATCH_NO :
				imap_match(glob, cur_prefix);

			if (match == IMAP_MATCH_YES) {
				/* The prefix itself matches */
				string_t *str = t_str_new(128);
				str_printfa(str, "* LIST (%s) \"%s\" ",
					mailbox_flags2str(MAILBOX_PLACEHOLDER,
							  list_flags),
					ns->sep_str);
				len = strlen(ns->prefix);
				imap_quote_append_string(str,
					t_strndup(ns->prefix, len-1), FALSE);
				client_send_line(client, str_c(str));
			}
		}

		if (match >= 0) {
			unsigned int count = 0;
			if (*cur_prefix != '\0') {
				/* we'll have to fix mask */
				for (; *cur_prefix != '\0'; cur_prefix++) {
					if (*cur_prefix == ns->sep)
						count++;
				}
				if (count == 0)
					count = 1;

				while (count > 0) {
					if (*cur_ref != '\0') {
						while (*cur_ref != '\0' &&
						       *cur_ref++ != ns->sep)
							;
					} else {
						while (*cur_mask != '\0' &&
						       *cur_mask != '*' &&
						       *cur_mask != ns->sep)
							cur_mask++;
						if (*cur_mask == '*') {
							cur_mask = "*";
							break;
						}
						if (*cur_mask == '\0')
							break;
						cur_mask++;
					}
					count--;
				}
			}

			if (*cur_mask != '*' || strcmp(mask, "*") == 0)
				glob = NULL;

			cur_ref = namespace_fix_sep(ns, cur_ref);
			cur_mask = namespace_fix_sep(ns, cur_mask);

			ctx = mail_storage_mailbox_list_init(ns->storage,
							     cur_ref, cur_mask,
							     list_flags);
			if (list_namespace_mailboxes(client, glob, ns, ctx,
						     list_flags) < 0) {
				client_send_storage_error(client, ns->storage);
				t_pop();
				return -1;
			}
		}
		t_pop();
	}

	return 0;
}

int _cmd_list_full(struct client *client, int lsub)
{
	struct namespace *ns;
	struct imap_arg *args;
        enum mailbox_list_flags list_flags;
	const char *ref, *mask;

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

	if (*mask == '\0' && !lsub) {
		/* special request to return the hierarchy delimiter */
		ns = namespace_find(client->namespaces, &ref);
		if (ns == NULL) {
			const char *empty = "";
			ns = namespace_find(client->namespaces, &empty);
		}

		if (ns != NULL) {
			client_send_line(client, t_strconcat(
				"* LIST (\\Noselect) \"", ns->sep_str,
				"\" \"\"", NULL));
		}
	} else {
		if (list_mailboxes(client, ref, mask, list_flags) < 0)
			return TRUE;
	}

	client_send_tagline(client, !lsub ?
			    "OK List completed." :
			    "OK Lsub completed.");
	return TRUE;
}

int cmd_list(struct client *client)
{
	return _cmd_list_full(client, FALSE);
}
