/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "message-address.h"
#include "message-header-decode.h"
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

struct mail_sort_node_float {
	uint32_t seq;
	float num;
};
ARRAY_DEFINE_TYPE(mail_sort_node_float, struct mail_sort_node_float);

struct sort_cmp_context {
	struct mail_search_sort_program *program;
	struct mail *mail;
	bool reverse;
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

static uoff_t index_sort_get_pop3_order(struct mail *mail)
{
	const char *str;
	uoff_t size;

	if (mail_get_special(mail, MAIL_FETCH_POP3_ORDER, &str) < 0 ||
	    str_to_uoff(str, &size) < 0)
		return (uint32_t)-1;
	else
		return size;
}

static void
index_sort_list_add_pop3_order(struct mail_search_sort_program *program,
			       struct mail *mail)
{
	ARRAY_TYPE(mail_sort_node_size) *nodes = program->context;
	struct mail_sort_node_size *node;

	node = array_append_space(nodes);
	node->seq = mail->seq;
	node->size = index_sort_get_pop3_order(mail);
}

static float index_sort_get_score(struct mail *mail)
{
	const char *str;

	if (mail_get_special(mail, MAIL_FETCH_SEARCH_SCORE, &str) < 0)
		return 0;
	else
		return strtod(str, NULL);
}

static void
index_sort_list_add_score(struct mail_search_sort_program *program,
			  struct mail *mail)
{
	ARRAY_TYPE(mail_sort_node_float) *nodes = program->context;
	struct mail_sort_node_float *node;

	node = array_append_space(nodes);
	node->seq = mail->seq;
	node->num = index_sort_get_score(mail);
}

void index_sort_list_add(struct mail_search_sort_program *program,
			 struct mail *mail)
{
	i_assert(mail->transaction == program->t);

	program->sort_list_add(program, mail);
}

static int sort_node_date_cmp(const struct mail_sort_node_date *n1,
			      const struct mail_sort_node_date *n2)
{
	struct sort_cmp_context *ctx = &static_node_cmp_context;

	if (n1->date < n2->date)
		return !ctx->reverse ? -1 : 1;
	if (n1->date > n2->date)
		return !ctx->reverse ? 1 : -1;

	return index_sort_node_cmp_type(ctx->mail,
					ctx->program->sort_program + 1,
					n1->seq, n2->seq);
}

static void
index_sort_list_finish_date(struct mail_search_sort_program *program)
{
	ARRAY_TYPE(mail_sort_node_date) *nodes = program->context;

	array_sort(nodes, sort_node_date_cmp);
	memcpy(&program->seqs, nodes, sizeof(program->seqs));
	i_free(nodes);
	program->context = NULL;
}

static int sort_node_size_cmp(const struct mail_sort_node_size *n1,
			      const struct mail_sort_node_size *n2)
{
	struct sort_cmp_context *ctx = &static_node_cmp_context;

	if (n1->size < n2->size)
		return !ctx->reverse ? -1 : 1;
	if (n1->size > n2->size)
		return !ctx->reverse ? 1 : -1;

	return index_sort_node_cmp_type(ctx->mail,
					ctx->program->sort_program + 1,
					n1->seq, n2->seq);
}

static void
index_sort_list_finish_size(struct mail_search_sort_program *program)
{
	ARRAY_TYPE(mail_sort_node_size) *nodes = program->context;

	array_sort(nodes, sort_node_size_cmp);
	memcpy(&program->seqs, nodes, sizeof(program->seqs));
	i_free(nodes);
	program->context = NULL;
}

static int sort_node_float_cmp(const struct mail_sort_node_float *n1,
			       const struct mail_sort_node_float *n2)
{
	struct sort_cmp_context *ctx = &static_node_cmp_context;

	if (n1->num < n2->num)
		return !ctx->reverse ? -1 : 1;
	if (n1->num > n2->num)
		return !ctx->reverse ? 1 : -1;

	return index_sort_node_cmp_type(ctx->mail,
					ctx->program->sort_program + 1,
					n1->seq, n2->seq);
}

static void
index_sort_list_finish_float(struct mail_search_sort_program *program)
{
	ARRAY_TYPE(mail_sort_node_float) *nodes = program->context;

	array_sort(nodes, sort_node_float_cmp);
	memcpy(&program->seqs, nodes, sizeof(program->seqs));
	i_free(nodes);
	program->context = NULL;
}

void index_sort_list_finish(struct mail_search_sort_program *program)
{
	memset(&static_node_cmp_context, 0, sizeof(static_node_cmp_context));
	static_node_cmp_context.program = program;
	static_node_cmp_context.mail = program->temp_mail;
	static_node_cmp_context.reverse =
		(program->sort_program[0] & MAIL_SORT_FLAG_REVERSE) != 0;

	program->sort_list_finish(program);
}

bool index_sort_list_next(struct mail_search_sort_program *program,
			  struct mail *mail)
{
	const uint32_t *seqp;

	if (program->iter_idx == array_count(&program->seqs))
		return FALSE;

	seqp = array_idx(&program->seqs, program->iter_idx++);
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

	for (i = 0; i < MAX_SORT_PROGRAM_SIZE; i++) {
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
	case MAIL_SORT_DISPLAYFROM:
	case MAIL_SORT_DISPLAYTO:
		program->sort_list_add = index_sort_list_add_string;
		program->sort_list_finish = index_sort_list_finish_string;
		index_sort_list_init_string(program);
		break;
	case MAIL_SORT_SEARCH_SCORE: {
		ARRAY_TYPE(mail_sort_node_float) *nodes;

		nodes = i_malloc(sizeof(*nodes));
		i_array_init(nodes, 128);
		program->sort_list_add = index_sort_list_add_score;
		program->sort_list_finish = index_sort_list_finish_float;
		program->context = nodes;
		break;
	}
	case MAIL_SORT_POP3_ORDER: {
		ARRAY_TYPE(mail_sort_node_size) *nodes;

		nodes = i_malloc(sizeof(*nodes));
		i_array_init(nodes, 128);
		program->sort_list_add = index_sort_list_add_pop3_order;
		program->sort_list_finish = index_sort_list_finish_size;
		program->context = nodes;
		break;
	}
	default:
		i_unreached();
	}
	return program;
}

void index_sort_program_deinit(struct mail_search_sort_program **_program)
{
	struct mail_search_sort_program *program = *_program;

	*_program = NULL;

	if (program->context != NULL)
		index_sort_list_finish(program);
	mail_free(&program->temp_mail);
	array_free(&program->seqs);
	i_free(program);
}

static int
get_first_addr(struct mail *mail, const char *header,
	       struct message_address **addr_r)
{
	const char *str;
	int ret;

	if ((ret = mail_get_first_header(mail, header, &str)) <= 0) {
		*addr_r = NULL;
		return ret;
	}

	*addr_r = message_address_parse(pool_datastack_create(),
					(const unsigned char *)str,
					strlen(str), 1, TRUE);
	return 0;
}

static int
get_first_mailbox(struct mail *mail, const char *header, const char **mailbox_r)
{
	struct message_address *addr;

	if (get_first_addr(mail, header, &addr) < 0) {
		*mailbox_r = "";
		return -1;
	}
	*mailbox_r = addr != NULL && addr->mailbox != NULL ? addr->mailbox : "";
	return 0;
}

static int
get_display_name(struct mail *mail, const char *header, const char **name_r)
{
	struct message_address *addr;

	*name_r = "";

	if (get_first_addr(mail, header, &addr) < 0)
		return -1;
	if (addr == NULL)
		return 0;

	if (addr->name != NULL) {
		string_t *str;
		unsigned int len = strlen(addr->name);

		str = t_str_new(len*2);
		(void)message_header_decode_utf8(
			(const unsigned char *)addr->name, len, str, FALSE);
		if (str_len(str) > 0) {
			*name_r = str_c(str);
			return 0;
		}
	}
	if (addr->mailbox != NULL && addr->domain != NULL)
		*name_r = t_strconcat(addr->mailbox, "@", addr->domain, NULL);
	else if (addr->mailbox != NULL)
		*name_r = addr->mailbox;
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
	case MAIL_SORT_DISPLAYFROM:
		ret = get_display_name(mail, "From", &str);
		break;
	case MAIL_SORT_DISPLAYTO:
		ret = get_display_name(mail, "To", &str);
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
	float float1, float2;
	int ret = 0;

	sort_type = *sort_program & MAIL_SORT_MASK;
	switch (sort_type) {
	case MAIL_SORT_CC:
	case MAIL_SORT_FROM:
	case MAIL_SORT_TO:
	case MAIL_SORT_SUBJECT:
	case MAIL_SORT_DISPLAYFROM:
	case MAIL_SORT_DISPLAYTO:
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
	case MAIL_SORT_SEARCH_SCORE:
		mail_set_seq(mail, seq1);
		float1 = index_sort_get_score(mail);
		mail_set_seq(mail, seq2);
		float2 = index_sort_get_score(mail);

		ret = float1 < float2 ? -1 :
			(float1 > float2 ? 1 : 0);
		break;
	case MAIL_SORT_POP3_ORDER:
		/* 32bit numbers would be enough, but since there is already
		   existing code for uoff_t in sizes, just use them. */
		mail_set_seq(mail, seq1);
		size1 = index_sort_get_pop3_order(mail);
		mail_set_seq(mail, seq2);
		size2 = index_sort_get_pop3_order(mail);

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

	if ((*sort_program & MAIL_SORT_FLAG_REVERSE) != 0)
		ret = ret < 0 ? 1 : -1;
	return ret;
}
