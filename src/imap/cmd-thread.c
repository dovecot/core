/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "ostream.h"
#include "imap-base-subject.h"
#include "imap-commands.h"
#include "imap-search-args.h"
#include "mail-thread.h"

static int imap_thread_write(struct mail_thread_iterate_context *iter,
			     string_t *str, bool root)
{
	const struct mail_thread_child_node *node;
	struct mail_thread_iterate_context *child_iter;
	unsigned int count;
	int ret = 0;

	count = mail_thread_iterate_count(iter);
	if (count == 0)
		return 0;

	if (count == 1 && !root) {
		/* only one child - special case to avoid extra parenthesis */
		node = mail_thread_iterate_next(iter, &child_iter);
		str_printfa(str, "%u", node->uid);
		if (child_iter != NULL) {
			str_append_c(str, ' ');
			T_BEGIN {
				ret = imap_thread_write(child_iter, str, FALSE);
			} T_END;
			if (mail_thread_iterate_deinit(&child_iter) < 0)
				return -1;
		}
		return ret;
	}

	while ((node = mail_thread_iterate_next(iter, &child_iter)) != NULL) {
		if (child_iter == NULL) {
			/* no children */
			str_printfa(str, "(%u)", node->uid);
		} else {
			/* node with children */
			str_append_c(str, '(');
			if (node->uid != 0)
				str_printfa(str, "%u ", node->uid);
			T_BEGIN {
				ret = imap_thread_write(child_iter, str, FALSE);
			} T_END;
			if (mail_thread_iterate_deinit(&child_iter) < 0 ||
			    ret < 0)
				return -1;
			str_append_c(str, ')');
		}
	}
	return 0;
}

static int
imap_thread_write_reply(struct mail_thread_context *ctx, string_t *str,
			enum mail_thread_type thread_type, bool write_seqs)
{
	struct mail_thread_iterate_context *iter;
	int ret;

	iter = mail_thread_iterate_init(ctx, thread_type, write_seqs);
	str_append(str, "* THREAD ");
	T_BEGIN {
		ret = imap_thread_write(iter, str, TRUE);
	} T_END;
	if (mail_thread_iterate_deinit(&iter) < 0)
		ret = -1;

	str_append(str, "\r\n");
	return ret;
}

static int imap_thread(struct client_command_context *cmd,
		       struct mail_search_args *search_args,
		       enum mail_thread_type thread_type)
{
	struct mail_thread_context *ctx;
	string_t *str;
	int ret;

	i_assert(thread_type == MAIL_THREAD_REFERENCES ||
		 thread_type == MAIL_THREAD_REFS);

	str = str_new(default_pool, 1024);
	ret = mail_thread_init(cmd->client->mailbox,
			       search_args, &ctx);
	if (ret == 0) {
		ret = imap_thread_write_reply(ctx, str, thread_type,
					      !cmd->uid);
		mail_thread_deinit(&ctx);
	}

	if (ret == 0)
		o_stream_nsend(cmd->client->output, str_data(str), str_len(str));
	str_free(&str);
	return ret;
}

struct orderedsubject_thread {
	time_t timestamp;
	ARRAY_TYPE(uint32_t) msgs;
};

static int orderedsubject_thread_cmp(const struct orderedsubject_thread *t1,
				     const struct orderedsubject_thread *t2)
{
	const uint32_t *m1, *m2;

	if (t1->timestamp < t2->timestamp)
		return -1;
	if (t1->timestamp > t2->timestamp)
		return 1;

	m1 = array_first(&t1->msgs);
	m2 = array_first(&t2->msgs);
	if (*m1 < *m2)
		return -1;
	if (*m1 > *m2)
		return 1;
	i_unreached();
}

static void
imap_orderedsubject_thread_write(struct ostream *output, string_t *reply,
				 const struct orderedsubject_thread *thread)
{
	const uint32_t *msgs;
	unsigned int i, count;

	if (str_len(reply) > 128-10) {
		o_stream_nsend(output, str_data(reply), str_len(reply));
		str_truncate(reply, 0);
	}

	msgs = array_get(&thread->msgs, &count);
	switch (count) {
	case 1:
		str_printfa(reply, "(%u)", msgs[0]);
		break;
	case 2:
		str_printfa(reply, "(%u %u)", msgs[0], msgs[1]);
		break;
	default:
		/* (1 (2)(3)) */
		str_printfa(reply, "(%u ", msgs[0]);
		for (i = 1; i < count; i++) {
			if (str_len(reply) > 128-10) {
				o_stream_nsend(output, str_data(reply),
					       str_len(reply));
				str_truncate(reply, 0);
			}
			str_printfa(reply, "(%u)", msgs[i]);
		}
		str_append_c(reply, ')');
	}
}

static int imap_thread_orderedsubject(struct client_command_context *cmd,
				      struct mail_search_args *search_args)
{
	static const enum mail_sort_type sort_program[] = {
		MAIL_SORT_SUBJECT,
		MAIL_SORT_DATE,
		0
	};
	struct mailbox_transaction_context *trans;
	struct mail_search_context *search_ctx;
	struct mail *mail;
	string_t *prev_subject, *reply;
	const char *subject, *base_subject;
	pool_t pool;
	ARRAY(struct orderedsubject_thread) threads;
	const struct orderedsubject_thread *thread;
	struct orderedsubject_thread *cur_thread = NULL;
	uint32_t num;
	bool reply_or_fw;
	int ret, tz;

	prev_subject = str_new(default_pool, 128);

	/* first read all of the threads into memory */
	pool = pool_alloconly_create("orderedsubject thread", 1024);
	i_array_init(&threads, 128);
	trans = mailbox_transaction_begin(cmd->client->mailbox, 0,
					  imap_client_command_get_reason(cmd));
	search_ctx = mailbox_search_init(trans, search_args, sort_program,
					 0, NULL);
	while (mailbox_search_next(search_ctx, &mail)) {
		if (mail_get_first_header(mail, "Subject", &subject) <= 0)
			subject = "";
		T_BEGIN {
			base_subject = imap_get_base_subject_cased(
					pool_datastack_create(), subject,
					&reply_or_fw);
			if (strcmp(str_c(prev_subject), base_subject) != 0) {
				/* thread changed */
				cur_thread = NULL;
			}
			str_truncate(prev_subject, 0);
			str_append(prev_subject, base_subject);
		} T_END;

		if (cur_thread == NULL) {
			/* starting a new thread. get the first message's
			   date */
			cur_thread = array_append_space(&threads);
			if (mail_get_date(mail, &cur_thread->timestamp,
					  &tz) == 0 &&
			    cur_thread->timestamp == 0) {
				(void)mail_get_received_date(mail,
					&cur_thread->timestamp);
			}
			p_array_init(&cur_thread->msgs, pool, 4);
		}
		num = cmd->uid ? mail->uid : mail->seq;
		array_append(&cur_thread->msgs, &num, 1);
	}
	str_free(&prev_subject);
	ret = mailbox_search_deinit(&search_ctx);
	(void)mailbox_transaction_commit(&trans);
	if (ret < 0) {
		array_free(&threads);
		pool_unref(&pool);
		return -1;
	}

	/* sort the threads by their first message's timestamp */
	array_sort(&threads, orderedsubject_thread_cmp);

	/* write the threads to client */
	reply = t_str_new(128);
	str_append(reply, "* THREAD ");
	array_foreach(&threads, thread) {
		imap_orderedsubject_thread_write(cmd->client->output,
						 reply, thread);
	}
	str_append(reply, "\r\n");
	o_stream_nsend(cmd->client->output, str_data(reply), str_len(reply));

	array_free(&threads);
	pool_unref(&pool);
	return 0;
}

bool cmd_thread(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	enum mail_thread_type thread_type;
	struct mail_search_args *sargs;
	const struct imap_arg *args;
	const char *charset, *str;
	int ret;

	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!client_verify_open_mailbox(cmd))
		return TRUE;

	if (!imap_arg_get_astring(&args[0], &str) ||
	    !imap_arg_get_astring(&args[1], &charset)) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}
	args += 2;

	if (!mail_thread_type_parse(str, &thread_type)) {
		client_send_command_error(cmd, "Unknown thread algorithm.");
		return TRUE;
	}

	ret = imap_search_args_build(cmd, args, charset, &sargs);
	if (ret <= 0)
		return ret < 0;

	if (thread_type != MAIL_THREAD_ORDEREDSUBJECT)
		ret = imap_thread(cmd, sargs, thread_type);
	else
		ret = imap_thread_orderedsubject(cmd, sargs);
	mail_search_args_unref(&sargs);
	if (ret < 0) {
		client_send_box_error(cmd, client->mailbox);
		return TRUE;
	}

	return cmd_sync(cmd, MAILBOX_SYNC_FLAG_FAST |
			(cmd->uid ? 0 : MAILBOX_SYNC_FLAG_NO_EXPUNGES),
			0, "OK Thread completed.");
}
