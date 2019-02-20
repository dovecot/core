/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "unichar.h"
#include "message-address.h"
#include "message-header-decode.h"
#include "imap-base-subject.h"
#include "index-storage.h"
#include "index-sort-private.h"


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
	bool reverse;
};

static struct sort_cmp_context static_node_cmp_context;

static void
index_sort_program_set_mail_failed(struct mail_search_sort_program *program,
				   struct mail *mail)
{
	switch (mailbox_get_last_mail_error(mail->box)) {
	case MAIL_ERROR_EXPUNGED:
		break;
	case MAIL_ERROR_LOOKUP_ABORTED:
		/* just change the error message */
		i_assert(program->slow_mails_left == 0);
		mail_storage_set_error(program->t->box->storage, MAIL_ERROR_LIMIT,
			"Requested sort would have taken too long.");
		/* fall through */
	default:
		program->failed = TRUE;
		break;
	}
}

static time_t
index_sort_program_set_date_failed(struct mail_search_sort_program *program,
				   struct mail *mail)
{
	index_sort_program_set_mail_failed(program, mail);

	if (mailbox_get_last_mail_error(mail->box) == MAIL_ERROR_LIMIT) {
		/* limit reached - sort the rest of the mails at the end of
		   the list by their UIDs */
		return LONG_MAX;
	} else {
		/* expunged / some other error - sort in the beginning */
		return 0;
	}
}

static void
index_sort_list_add_arrival(struct mail_search_sort_program *program,
			    struct mail *mail)
{
	ARRAY_TYPE(mail_sort_node_date) *nodes = program->context;
	struct mail_sort_node_date *node;

	node = array_append_space(nodes);
	node->seq = mail->seq;
	if (mail_get_received_date(mail, &node->date) < 0)
		node->date = index_sort_program_set_date_failed(program, mail);
}

static void
index_sort_list_add_date(struct mail_search_sort_program *program,
			 struct mail *mail)
{
	ARRAY_TYPE(mail_sort_node_date) *nodes = program->context;
	struct mail_sort_node_date *node;
	int tz;

	node = array_append_space(nodes);
	node->seq = mail->seq;
	if (mail_get_date(mail, &node->date, &tz) < 0)
		node->date = index_sort_program_set_date_failed(program, mail);
	else if (node->date == 0) {
		if (mail_get_received_date(mail, &node->date) < 0)
			node->date = index_sort_program_set_date_failed(program, mail);
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
	if (mail_get_virtual_size(mail, &node->size) < 0) {
		index_sort_program_set_mail_failed(program, mail);
		node->size = 0;
	}
}

static int index_sort_get_pop3_order(struct mail *mail, uoff_t *size_r)
{
	const char *str;

	if (mail_get_special(mail, MAIL_FETCH_POP3_ORDER, &str) < 0) {
		*size_r = (uint32_t)-1;
		return -1;
	}

	if (str_to_uoff(str, size_r) < 0)
		*size_r = (uint32_t)-1;
	return 0;
}

static void
index_sort_list_add_pop3_order(struct mail_search_sort_program *program,
			       struct mail *mail)
{
	ARRAY_TYPE(mail_sort_node_size) *nodes = program->context;
	struct mail_sort_node_size *node;

	node = array_append_space(nodes);
	node->seq = mail->seq;
	(void)index_sort_get_pop3_order(mail, &node->size);
}

static int index_sort_get_relevancy(struct mail *mail, float *result_r)
{
	const char *str;

	if (mail_get_special(mail, MAIL_FETCH_SEARCH_RELEVANCY, &str) < 0) {
		*result_r = 0;
		return -1;
	}
	*result_r = strtod(str, NULL);
	return 0;
}

static void
index_sort_list_add_relevancy(struct mail_search_sort_program *program,
			      struct mail *mail)
{
	ARRAY_TYPE(mail_sort_node_float) *nodes = program->context;
	struct mail_sort_node_float *node;

	node = array_append_space(nodes);
	node->seq = mail->seq;
	(void)index_sort_get_relevancy(mail, &node->num);
}

void index_sort_list_add(struct mail_search_sort_program *program,
			 struct mail *mail)
{
	enum mail_access_type orig_access_type = mail->access_type;
	bool prev_slow = mail->mail_stream_opened ||
		mail->mail_metadata_accessed;

	i_assert(mail->transaction == program->t);
	/* if lookup_abort isn't NEVER, mail_sort_max_read_count handling
	   doesn't work right. */
	i_assert(mail->lookup_abort == MAIL_LOOKUP_ABORT_NEVER);

	if (program->slow_mails_left == 0)
		mail->lookup_abort = MAIL_LOOKUP_ABORT_NOT_IN_CACHE;

	mail->access_type = MAIL_ACCESS_TYPE_SORT;
	T_BEGIN {
		program->sort_list_add(program, mail);
	} T_END;
	mail->access_type = orig_access_type;

	if (!prev_slow && (mail->mail_stream_opened ||
			   mail->mail_metadata_accessed)) {
		i_assert(program->slow_mails_left > 0);
		program->slow_mails_left--;
	}
	mail->lookup_abort = MAIL_LOOKUP_ABORT_NEVER;
}

static int sort_node_date_cmp(const struct mail_sort_node_date *n1,
			      const struct mail_sort_node_date *n2)
{
	struct sort_cmp_context *ctx = &static_node_cmp_context;

	if (n1->date < n2->date)
		return !ctx->reverse ? -1 : 1;
	if (n1->date > n2->date)
		return !ctx->reverse ? 1 : -1;

	return index_sort_node_cmp_type(ctx->program,
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

	return index_sort_node_cmp_type(ctx->program,
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

	return index_sort_node_cmp_type(ctx->program,
					ctx->program->sort_program + 1,
					n1->seq, n2->seq);
}

static void
index_sort_list_finish_float(struct mail_search_sort_program *program)
{
	ARRAY_TYPE(mail_sort_node_float) *nodes = program->context;

	/* NOTE: higher relevancy is returned first, unlike with all
	   other number based sort keys, so temporarily reverse the search */
	static_node_cmp_context.reverse = !static_node_cmp_context.reverse;
	array_sort(nodes, sort_node_float_cmp);
	static_node_cmp_context.reverse = !static_node_cmp_context.reverse;

	memcpy(&program->seqs, nodes, sizeof(program->seqs));
	i_free(nodes);
	program->context = NULL;
}

void index_sort_list_finish(struct mail_search_sort_program *program)
{
	i_zero(&static_node_cmp_context);
	static_node_cmp_context.program = program;
	static_node_cmp_context.reverse =
		(program->sort_program[0] & MAIL_SORT_FLAG_REVERSE) != 0;

	program->sort_list_finish(program);
}

bool index_sort_list_next(struct mail_search_sort_program *program,
			  uint32_t *seq_r)
{
	const uint32_t *seqp;

	if (program->iter_idx == array_count(&program->seqs))
		return FALSE;

	seqp = array_idx(&program->seqs, program->iter_idx++);
	*seq_r = *seqp;
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
	program->temp_mail->access_type = MAIL_ACCESS_TYPE_SORT;

	program->slow_mails_left =
		program->t->box->storage->set->mail_sort_max_read_count;
	if (program->slow_mails_left == 0)
		program->slow_mails_left = UINT_MAX;

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
	case MAIL_SORT_RELEVANCY: {
		ARRAY_TYPE(mail_sort_node_float) *nodes;

		nodes = i_malloc(sizeof(*nodes));
		i_array_init(nodes, 128);
		program->sort_list_add = index_sort_list_add_relevancy;
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

int index_sort_program_deinit(struct mail_search_sort_program **_program)
{
	struct mail_search_sort_program *program = *_program;

	*_program = NULL;

	if (program->context != NULL)
		index_sort_list_finish(program);
	mail_free(&program->temp_mail);
	array_free(&program->seqs);

	int ret = program->failed ? -1 : 0;
	i_free(program);
	return ret;
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
					strlen(str), 1,
					MESSAGE_ADDRESS_PARSE_FLAG_FILL_MISSING);
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
		size_t len = strlen(addr->name);

		str = t_str_new(len*2);
		(void)message_header_decode_utf8(
			(const unsigned char *)addr->name, len, str, NULL);
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

static void
index_sort_set_seq(struct mail_search_sort_program *program,
		   struct mail *mail, uint32_t seq)
{
	if ((mail->mail_stream_opened || mail->mail_metadata_accessed) &&
	    program->slow_mails_left > 0)
		program->slow_mails_left--;
	mail_set_seq(mail, seq);
	if (program->slow_mails_left == 0) {
		/* too many slow lookups - just return the rest of the results
		   in whatever order. */
		mail->lookup_abort = MAIL_LOOKUP_ABORT_NOT_IN_CACHE;
	}
}

int index_sort_header_get(struct mail_search_sort_program *program, uint32_t seq,
			  enum mail_sort_type sort_type, string_t *dest)
{
	struct mail *mail = program->temp_mail;
	const char *str;
	int ret;
	bool reply_or_fw;

	index_sort_set_seq(program, mail, seq);
	str_truncate(dest, 0);

	switch (sort_type & MAIL_SORT_MASK) {
	case MAIL_SORT_SUBJECT:
		ret = mail_get_first_header(mail, "Subject", &str);
		if (ret < 0)
			break;
		if (ret == 0) {
			/* nonexistent header */
			return 1;
		}
		str = imap_get_base_subject_cased(pool_datastack_create(),
						  str, &reply_or_fw);
		str_append(dest, str);
		return 1;
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
	if (ret < 0) {
		index_sort_program_set_mail_failed(program, mail);
		if (!program->failed)
			return 0;
		return -1;
	}

	(void)uni_utf8_to_decomposed_titlecase(str, strlen(str), dest);
	return 1;
}

int index_sort_node_cmp_type(struct mail_search_sort_program *program,
			     const enum mail_sort_type *sort_program,
			     uint32_t seq1, uint32_t seq2)
{
	struct mail *mail = program->temp_mail;
	enum mail_sort_type sort_type;
	time_t time1, time2;
	uoff_t size1, size2;
	float float1, float2;
	int tz, ret = 0;

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
			if (index_sort_header_get(program, seq1, sort_type, str1) < 0)
				index_sort_program_set_mail_failed(program, mail);
			if (index_sort_header_get(program, seq2, sort_type, str2) < 0)
				index_sort_program_set_mail_failed(program, mail);

			ret = strcmp(str_c(str1), str_c(str2));
		} T_END;
		break;
	case MAIL_SORT_ARRIVAL:
		index_sort_set_seq(program, mail, seq1);
		if (mail_get_received_date(mail, &time1) < 0)
			time1 = index_sort_program_set_date_failed(program, mail);

		index_sort_set_seq(program, mail, seq2);
		if (mail_get_received_date(mail, &time2) < 0)
			time2 = index_sort_program_set_date_failed(program, mail);

		ret = time1 < time2 ? -1 :
			(time1 > time2 ? 1 : 0);
		break;
	case MAIL_SORT_DATE:
		index_sort_set_seq(program, mail, seq1);
		if (mail_get_date(mail, &time1, &tz) < 0)
			time1 = index_sort_program_set_date_failed(program, mail);
		else if (time1 == 0) {
			if (mail_get_received_date(mail, &time1) < 0)
				time1 = index_sort_program_set_date_failed(program, mail);
		}

		index_sort_set_seq(program, mail, seq2);
		if (mail_get_date(mail, &time2, &tz) < 0)
			time2 = index_sort_program_set_date_failed(program, mail);
		else if (time2 == 0) {
			if (mail_get_received_date(mail, &time2) < 0)
				time2 = index_sort_program_set_date_failed(program, mail);
		}

		ret = time1 < time2 ? -1 :
			(time1 > time2 ? 1 : 0);
		break;
	case MAIL_SORT_SIZE:
		index_sort_set_seq(program, mail, seq1);
		if (mail_get_virtual_size(mail, &size1) < 0) {
			index_sort_program_set_mail_failed(program, mail);
			size1 = 0;
		}

		index_sort_set_seq(program, mail, seq2);
		if (mail_get_virtual_size(mail, &size2) < 0) {
			index_sort_program_set_mail_failed(program, mail);
			size2 = 0;
		}

		ret = size1 < size2 ? -1 :
			(size1 > size2 ? 1 : 0);
		break;
	case MAIL_SORT_RELEVANCY:
		index_sort_set_seq(program, mail, seq1);
		if (index_sort_get_relevancy(mail, &float1) < 0)
			index_sort_program_set_mail_failed(program, mail);
		index_sort_set_seq(program, mail, seq2);
		if (index_sort_get_relevancy(mail, &float2) < 0)
			index_sort_program_set_mail_failed(program, mail);

		/* NOTE: higher relevancy is returned first, unlike with all
		   other number based sort keys */
		ret = float1 < float2 ? 1 :
			(float1 > float2 ? -1 : 0);
		break;
	case MAIL_SORT_POP3_ORDER:
		/* 32bit numbers would be enough, but since there is already
		   existing code for uoff_t in sizes, just use them. */
		index_sort_set_seq(program, mail, seq1);
		if (index_sort_get_pop3_order(mail, &size1) < 0)
			index_sort_program_set_mail_failed(program, mail);
		index_sort_set_seq(program, mail, seq2);
		if (index_sort_get_pop3_order(mail, &size2) < 0)
			index_sort_program_set_mail_failed(program, mail);

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
		return index_sort_node_cmp_type(program, sort_program+1,
						seq1, seq2);
	}

	if ((*sort_program & MAIL_SORT_FLAG_REVERSE) != 0)
		ret = ret < 0 ? 1 : -1;
	return ret;
}
