/* Copyright (c) 2010 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "base64.h"
#include "randgen.h"
#include "str.h"
#include "imap-quote.h"
#include "imap-parser.h"
#include "mail-storage.h"
#include "mail-search-build.h"
#include "doveadm-mail.h"

static struct mail_search_args *search_args_from_str(const char *str)
{
	struct istream *input;
	struct imap_parser *parser;
	const struct imap_arg *args;
	struct mail_search_args *sargs;
	const char *error;
	bool fatal;
	int ret;

	input = i_stream_create_from_data(str, strlen(str));
	(void)i_stream_read(input);

	parser = imap_parser_create(input, NULL, (size_t)-1);
	ret = imap_parser_finish_line(parser, 0,  0, &args);
	if (ret < 0)
		i_fatal("%s", imap_parser_get_error(parser, &fatal));
	if (mail_search_build_from_imap_args(mail_search_register_human,
					     args, "UTF-8", &sargs, &error) < 0)
		i_fatal("%s", error);

	imap_parser_destroy(&parser);
	i_stream_destroy(&input);
	return sargs;
}

static const char *params_to_imap_args_string(const char *const args[])
{
	string_t *str;
	const char *p;

	str = t_str_new(256);
	for (; *args != NULL; args++) {
		for (p = *args; *p != '\0'; p++) {
			if (IS_ATOM_SPECIAL_INPUT(*p))
				break;
		}
		if (*p == '\0' ||
		    strcmp(*args, "(") == 0 ||
		    strcmp(*args, ")") == 0)
			str_append(str, *args);
		else
			imap_dquote_append(str, *args);
		str_append_c(str, ' ');
	}
	return str_c(str);
}

void cmd_fetch(struct mail_user *user, const char *const args[])
{
	const char *mailbox = args[0];
	struct mail_storage *storage;
	struct mailbox *box;
	struct mail_search_args *search_args;
	struct mailbox_transaction_context *t;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	struct istream *input;
	struct ostream *output;
	string_t *prefix;
	unsigned char prefix_buf[9];
	unsigned int prefix_len;

	if (mailbox == NULL || args[1] == NULL)
		doveadm_mail_help_name("fetch");
	search_args = search_args_from_str(params_to_imap_args_string(args+1));

	random_fill_weak(prefix_buf, sizeof(prefix_buf));
	prefix = t_str_new(32);
	str_append(prefix, "===");
	base64_encode(prefix_buf, sizeof(prefix_buf), prefix);
	str_append_c(prefix, ' ');
	prefix_len = str_len(prefix);

	output = o_stream_create_fd(STDOUT_FILENO, 0, FALSE);
	box = doveadm_mailbox_find_and_sync(user, mailbox);
	storage = mailbox_get_storage(box);

	t = mailbox_transaction_begin(box, 0);
	search_ctx = mailbox_search_init(t, search_args, NULL);
	mail = mail_alloc(t, 0, NULL);
	while (mailbox_search_next(search_ctx, mail)) {
		if (mail_get_stream(mail, NULL, NULL, &input) < 0) {
			i_error("Couldn't open mail uid=%u: %s", mail->uid,
				mail_storage_get_last_error(storage, NULL));
			continue;
		}

		str_truncate(prefix, prefix_len);
		str_printfa(prefix, "seq=%u uid=%u\n", mail->seq, mail->uid);
		if (o_stream_send(output, str_data(prefix), str_len(prefix)) < 0)
			i_fatal("write(stdout) failed: %m");

		while (!i_stream_is_eof(input)) {
			if (o_stream_send_istream(output, input) <= 0)
				i_fatal("write(stdout) failed: %m");
		}
	}
	mail_free(&mail);
	if (mailbox_search_deinit(&search_ctx) < 0) {
		i_fatal("Search failed: %s",
			mail_storage_get_last_error(storage, NULL));
	}
	(void)mailbox_transaction_commit(&t);
	mailbox_free(&box);
	o_stream_unref(&output);
}
