#ifndef __INDEX_MAIL_H
#define __INDEX_MAIL_H

#include "message-size.h"
#include "mail-cache.h"
#include "mail-storage-private.h"

struct message_header_line;

struct index_mail_data {
	struct mail_full_flags flags;
	time_t date, received_date;
	uoff_t size;

	struct mail_sent_date sent_date;

	buffer_t *headers;
	string_t *header_data;
	int header_data_cached, header_data_cached_contiguous;
	size_t header_data_uncached_offset;
	struct istream *header_stream;
	int header_save_idx;

	struct message_part *parts;
	const char *envelope, *body, *bodystructure, *uid_string;
	struct message_part_envelope_data *envelope_data;

	uint32_t seq;
	const struct mail_index_record *rec;

	struct istream *stream;
	struct message_size hdr_size, body_size;
	struct message_parser_ctx *parser_ctx;
	int parsing_count;

	unsigned int parse_header:1;
	unsigned int bodystructure_header_want:1;
	unsigned int bodystructure_header_parse:1;
	unsigned int bodystructure_header_parsed:1;
	unsigned int save_envelope:1;
	unsigned int save_sent_date:1;
	unsigned int hdr_size_set:1;
	unsigned int body_size_set:1;
	unsigned int deleted:1;
	unsigned int header_data_cached_partial:1;
	unsigned int header_fully_parsed:1;
	unsigned int header_save:1;
	unsigned int open_mail:1;
};

struct index_mail {
	struct mail mail;
	struct index_mail_data data;

	pool_t pool;
	struct index_mailbox *ibox;
	struct index_transaction_context *trans;
	unsigned int expunge_counter;
	buffer_t *header_buf;
	uint32_t uid_validity;

	enum mail_fetch_field wanted_fields;
	const char *const *wanted_headers;
	int wanted_headers_idx;
};

void index_mail_init(struct index_transaction_context *t,
		     struct index_mail *mail,
		     enum mail_fetch_field wanted_fields,
		     const char *const wanted_headers[]);
int index_mail_next(struct index_mail *mail, uint32_t seq);
void index_mail_deinit(struct index_mail *mail);

void index_mail_parse_header_init(struct index_mail *mail,
				  const char *const headers[]);
int index_mail_parse_header(struct message_part *part,
			    struct message_header_line *hdr,
			    struct index_mail *mail);

void index_mail_cache_transaction_begin(struct index_mail *mail);
int index_mail_parse_headers(struct index_mail *mail);

void index_mail_headers_init(struct index_mail *mail);
void index_mail_headers_init_next(struct index_mail *mail);
void index_mail_headers_close(struct index_mail *mail);

const char *index_mail_get_header(struct mail *_mail, const char *field);
struct istream *index_mail_get_headers(struct mail *_mail,
				       const char *const minimum_fields[]);

const struct mail_full_flags *index_mail_get_flags(struct mail *_mail);
const struct message_part *index_mail_get_parts(struct mail *_mail);
time_t index_mail_get_received_date(struct mail *_mail);
time_t index_mail_get_date(struct mail *_mail, int *timezone);
uoff_t index_mail_get_size(struct mail *_mail);
struct istream *index_mail_init_stream(struct index_mail *mail,
				       struct message_size *hdr_size,
				       struct message_size *body_size);
const char *index_mail_get_special(struct mail *_mail,
				   enum mail_fetch_field field);

int index_mail_update_flags(struct mail *mail,
			    const struct mail_full_flags *flags,
			    enum modify_type modify_type);
int index_mail_expunge(struct mail *mail);

const char *index_mail_get_cached_string(struct index_mail *mail,
					 enum mail_cache_field field);
uoff_t index_mail_get_cached_uoff_t(struct index_mail *mail,
				    enum mail_cache_field field);
uoff_t index_mail_get_cached_virtual_size(struct index_mail *mail);
time_t index_mail_get_cached_received_date(struct index_mail *mail);

#endif
