/* Copyright (c) 2006-2008 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "message-address.h"
#include "imap-base-subject.h"
#include "index-storage.h"
#include "index-sort-private.h"

#include <stdlib.h>

struct mail_sort_node_date {
	uint32_t seq;
	time_t date;
};
ARRAY_DEFINE_TYPE(mail_sort_node_date, struct mail_sort_node_date);

struct mail_sort_node_size {
	uint32_t seq;
	uoff_t size;
};
ARRAY_DEFINE_TYPE(mail_sort_node_size, struct mail_sort_node_size);

struct sort_cmp_context {
	struct mail_search_sort_program *program;
	struct mail *mail;
};

static struct sort_cmp_context static_node_cmp_context;

static void
index_sort_list_add_arrival(struct mail_search_sort_program *program,
			    struct mail *mail)
{
	ARRAY_TYPE(mail_sort_node_date) *nodes = program->context;
	struct mail_sort_node_date *node;

	node = array_append_space(nodes);
	node->seq = mail->seq;
	if (mail_get_received_date(mail, &node->date) < 0)
		node->date = 0;
}

static void
index_sort_list_add_date(struct mail_search_sort_program *program,
			 struct mail *mail)
{
	ARRAY_TYPE(mail_sort_node_date) *nodes = program->context;
	struct mail_sort_node_date *node;

	node = array_append_space(nodes);
	node->seq = mail->seq;
	if (mail_get_date(mail, &node->date, NULL) < 0)
		node->date = 0;
	else if (node->date == 0) {
		if (mail_get_received_date(mail, &node->date) < 0)
			node->date = 0;
	}
}

static void
index_sort_list_add_size(struct mail_search_sort_program *program,
			 struct mail *mail)
{
	ARRAY_TYPE(mail_sort_node_size) *nodes = program->context;
	struct mail_sort_node_size *node;

	node = array_append_space(nodes);
	node->seq = mail->seq;
	if (mail_get_virtual_size(mail, &node->size) < 0)
		node->size = 0;
}

void index_sort_list_add(struct mail_search_sort_program *program,
			 struct mail *mail)
{
	i_assert(mail->transaction == program->t);

	program->sort_list_add(program, mail);
}

static int sort_node_date_cmp(const void *p1, const void *p2)
{
	struct sort_cmp_context *ctx = &static_node_cmp_context;
	const struct mail_sort_node_date *n1 = p1, *n2 = p2;

	if (n1->date < n2->date)
		return -1;
	if (n1->date > n2->date)
		return 1;

	return index_sort_node_cmp_type(ctx->mail,
					ctx->program->sort_program + 1,
					n1->seq, n2->seq);
}

static void
index_sort_list_finish_date(struct mail_search_sort_program *program)
{
	ARRAY_TYPE(mail_sort_node_date) *nodes = program->context;
	struct mail_sort_node_date *date_nodes;
	unsigned int count;

	date_nodes = array_get_modifiable(nodes, &count);
	qsort(date_nodes, count, sizeof(struct mail_sort_node_date),
	      sort_node_date_cmp);
	memcpy(&program->seqs, nodes, sizeof(program->seqs));
	i_free(nodes);
	program->context = NULL;
}

static int sort_node_size_cmp(const void *p1, const void *p2)
{
	struct sort_cmp_context *ctx = &static_node_cmp_context;
	const struct mail_sort_node_size *n1 = p1, *n2 = p2;

	if (n1->size < n2->size)
		return -1;
	if (n1->size > n2->size)
		return 1;

	return index_sort_node_cmp_type(ctx->mail,
					ctx->program->sort_program + 1,
					n1->seq, n2->seq);
}

static void
index_sort_list_finish_size(struct mail_search_sort_program *program)
{
	ARRAY_TYPE(mail_sort_node_size) *nodes = program->context;
	struct mail_sort_node_size *size_nodes;
	unsigned int count;

	size_nodes = array_get_modifiable(nodes, &count);
	qsort(size_nodes, count, sizeof(struct mail_sort_node_size),
	      sort_node_size_cmp);
	memcpy(&program->seqs, nodes, sizeof(program->seqs));
	i_free(nodes);
	program->context = NULL;
}

void index_sort_list_finish(struct mail_search_sort_program *program)
{
	memset(&static_node_cmp_context, 0, sizeof(static_node_cmp_context));
	static_node_cmp_context.program = program;
	static_node_cmp_context.mail = program->temp_mail;

	program->sort_list_finish(program);

	if (program->reverse)
		program->iter_idx = array_count(&program->seqs);
}

bool index_sort_list_next(struct mail_search_sort_program *program,
			  struct mail *mail)
{
	const uint32_t *seqp;

	if (!program->reverse) {
		if (program->iter_idx == array_count(&program->seqs))
			return FALSE;

		seqp = array_idx(&program->seqs, program->iter_idx++);
	} else {
		if (program->iter_idx == 0)
			return FALSE;

		seqp = array_idx(&program->seqs, --program->iter_idx);
	}
	mail_set_seq(mail, *seqp);
	return TRUE;
}

struct mail_search_sort_program *
index_sort_program_init(struct mailbox_transaction_context *t,
			const enum mail_sort_type *sort_program)
{
	struct mail_search_sort_program *program;
	unsigned int i;

	if (sort_program == NULL || sort_program[0] == MAIL_SORT_END)
		return NULL;

	/* we support internal sorting by the primary condition */
	program = i_new(struct mail_search_sort_program, 1);
	program->t = t;
	program->temp_mail = mail_alloc(t, 0, NULL);

	/* primary reversion isn't stored to sort_program. we handle it by
	   iterating backwards at the end. */
	program->reverse = (sort_program[0] & MAIL_SORT_FLAG_REVERSE) != 0;
	program->sort_program[0] = sort_program[0] & ~MAIL_SORT_FLAG_REVERSE;
	for (i = 1; i < MAX_SORT_PROGRAM_SIZE; i++) {
		program->sort_program[i] = sort_program[i];
		if (sort_program[i] == MAIL_SORT_END)
			break;
	}
	if (i == MAX_SORT_PROGRAM_SIZE)
		i_panic("index_sort_program_init(): Invalid sort program");

	switch (program->sort_program[0] & MAIL_SORT_MASK) {
	case MAIL_SORT_ARRIVAL:
	case MAIL_SORT_DATE: {
		ARRAY_TYPE(mail_sort_node_date) *nodes;

		nodes = i_malloc(sizeof(*nodes));
		i_array_init(nodes, 128);

		if ((program->sort_program[0] &
		     MAIL_SORT_MASK) == MAIL_SORT_ARRIVAL)
			program->sort_list_add = index_sort_list_add_arrival;
		else
			program->sort_list_add = index_sort_list_add_date;
		program->sort_list_finish = index_sort_list_finish_date;
		program->context = nodes;
		break;
	}
	case MAIL_SORT_SIZE: {
		ARRAY_TYPE(mail_sort_node_size) *nodes;

		nodes = i_malloc(sizeof(*nodes));
		i_array_init(nodes, 128);
		program->sort_list_add = index_sort_list_add_size;
		program->sort_list_finish = index_sort_list_finish_size;
		program->context = nodes;
		break;
	}
	case MAIL_SORT_CC:
	case MAIL_SORT_FROM:
	case MAIL_SORT_SUBJECT:
	case MAIL_SORT_TO:
		program->sort_list_add = index_sort_list_add_string;
		program->sort_list_finish = index_sort_list_finish_string;
		index_sort_list_init_string(program);
		break;
	default:
		i_unreached();
	}
	return program;
}

void index_sort_program_deinit(struct mail_search_sort_program **_program)
{
	struct mail_search_sort_program *program = *_program;

	*_program = NULL;
	mail_free(&program->temp_mail);
	array_free(&program->seqs);
	i_free(program);
}

static int
get_first_mailbox(struct mail *mail, const char *header, const char **mailbox_r)
{
	struct message_address *addr;
	const char *str;
	int ret;

	if ((ret = mail_get_first_header_utf8(mail, header, &str)) <= 0) {
		*mailbox_r = "";
		return ret;
	}

	addr = message_address_parse(pool_datastack_create(),
				     (const unsigned char *)str,
				     strlen(str), 1, TRUE);
	*mailbox_r = addr != NULL ? addr->mailbox : "";
	return 0;
}

int index_sort_header_get(struct mail *mail, uint32_t seq,
			  enum mail_sort_type sort_type, string_t *dest)
{
	const char *str;
	int ret;

	mail_set_seq(mail, seq);
	str_truncate(dest, 0);

	switch (sort_type & MAIL_SORT_MASK) {
	case MAIL_SORT_SUBJECT:
		if ((ret = mail_get_first_header(mail, "Subject", &str)) <= 0)
			return ret;
		str = imap_get_base_subject_cased(pool_datastack_create(),
						  str, NULL);
		str_append(dest, str);
		return 0;
	case MAIL_SORT_CC:
		ret = get_first_mailbox(mail, "Cc", &str);
		break;
	case MAIL_SORT_FROM:
		ret = get_first_mailbox(mail, "From", &str);
		break;
	case MAIL_SORT_TO:
		ret = get_first_mailbox(mail, "To", &str);
		break;
	default:
		i_unreached();
	}

	(void)uni_utf8_to_decomposed_titlecase(str, (size_t)-1, dest);
	return ret;
}

int index_sort_node_cmp_type(struct mail *mail,
			     const enum mail_sort_type *sort_program,
			     uint32_t seq1, uint32_t seq2)
{
	enum mail_sort_type sort_type;
	time_t time1, time2;
	uoff_t size1, size2;
	int ret = 0;

	sort_type = *sort_program & MAIL_SORT_MASK;
	switch (sort_type) {
	case MAIL_SORT_CC:
	case MAIL_SORT_FROM:
	case MAIL_SORT_TO:
	case MAIL_SORT_SUBJECT:
		T_BEGIN {
			string_t *str1, *str2;

			str1 = t_str_new(256);
			str2 = t_str_new(256);
			index_sort_header_get(mail, seq1, sort_type, str1);
			index_sort_header_get(mail, seq2, sort_type, str2);

			ret = strcmp(str_c(str1), str_c(str2));
		} T_END;
		break;
	case MAIL_SORT_ARRIVAL:
		mail_set_seq(mail, seq1);
		if (mail_get_received_date(mail, &time1) < 0)
			time1 = 0;

		mail_set_seq(mail, seq2);
		if (mail_get_received_date(mail, &time2) < 0)
			time1 = 0;

		ret = time1 < time2 ? -1 :
			(time1 > time2 ? 1 : 0);
		break;
	case MAIL_SORT_DATE:
		mail_set_seq(mail, seq1);
		if (mail_get_date(mail, &time1, NULL) < 0)
			time1 = 0;
		else if (time1 == 0) {
			if (mail_get_received_date(mail, &time1) < 0)
				time1 = 0;
		}

		mail_set_seq(mail, seq2);
		if (mail_get_date(mail, &time2, NULL) < 0)
			time2 = 0;
		else if (time2 == 0) {
			if (mail_get_received_date(mail, &time2) < 0)
				time2 = 0;
		}

		ret = time1 < time2 ? -1 :
			(time1 > time2 ? 1 : 0);
		break;
	case MAIL_SORT_SIZE:
		mail_set_seq(mail, seq1);
		if (mail_get_virtual_size(mail, &size1) < 0)
			size1 = 0;

		mail_set_seq(mail, seq2);
		if (mail_get_virtual_size(mail, &size2) < 0)
			size2 = 0;

		ret = size1 < size2 ? -1 :
			(size1 > size2 ? 1 : 0);
		break;
	case MAIL_SORT_END:
		return seq1 < seq2 ? -1 :
			(seq1 > seq2 ? 1 : 0);
	case MAIL_SORT_MASK:
	case MAIL_SORT_FLAG_REVERSE:
		i_unreached();
	}

	if (ret == 0) {
		return index_sort_node_cmp_type(mail, sort_program+1,
						seq1, seq2);
	}

	/* primary reversion isn't in sort_program */
	if ((*sort_program & MAIL_SORT_FLAG_REVERSE) != 0)
		ret = ret < 0 ? 1 : -1;
	return ret;
}
