#ifndef INDEX_MAIL_H
#define INDEX_MAIL_H

#include "message-size.h"
#include "mail-cache.h"
#include "mail-storage-private.h"

enum index_cache_field {
	/* fixed size fields */
	MAIL_CACHE_FLAGS = 0,
	MAIL_CACHE_SENT_DATE,
	MAIL_CACHE_RECEIVED_DATE,
	MAIL_CACHE_SAVE_DATE,
	MAIL_CACHE_VIRTUAL_FULL_SIZE,
	MAIL_CACHE_PHYSICAL_FULL_SIZE,

	/* variable sized field */
	MAIL_CACHE_IMAP_BODY,
	MAIL_CACHE_IMAP_BODYSTRUCTURE,
	MAIL_CACHE_IMAP_ENVELOPE,
	MAIL_CACHE_POP3_UIDL,
	MAIL_CACHE_GUID,
	MAIL_CACHE_MESSAGE_PARTS,

	MAIL_INDEX_CACHE_FIELD_COUNT
};
extern struct mail_cache_field
	global_cache_fields[MAIL_INDEX_CACHE_FIELD_COUNT];

#define IMAP_BODY_PLAIN_7BIT_ASCII \
	"\"text\" \"plain\" (\"charset\" \"us-ascii\") NIL NIL \"7bit\""

enum mail_cache_record_flag {
	/* If binary flags are set, it's not checked whether mail is
	   missing CRs. So this flag may be set as an optimization for
	   regular non-binary mails as well if it's known that it contains
	   valid CR+LF line breaks. */
	MAIL_CACHE_FLAG_BINARY_HEADER		= 0x0001,
	MAIL_CACHE_FLAG_BINARY_BODY		= 0x0002,

	/* Mail header or body is known to contain NUL characters. */
	MAIL_CACHE_FLAG_HAS_NULS		= 0x0004,
	/* Mail header or body is known to not contain NUL characters. */
	MAIL_CACHE_FLAG_HAS_NO_NULS		= 0x0008,

	/* BODY is IMAP_BODY_PLAIN_7BIT_ASCII and rest of BODYSTRUCTURE
	   fields are NIL */
	MAIL_CACHE_FLAG_TEXT_PLAIN_7BIT_ASCII	= 0x0010
};

enum index_mail_access_part {
	READ_HDR	= 0x01,
	READ_BODY	= 0x02,
	PARSE_HDR	= 0x04,
	PARSE_BODY	= 0x08
};

struct mail_sent_date {
	uint32_t time;
	int32_t timezone;
};

struct index_mail_line {
	unsigned int field_idx;
	uint32_t start_pos, end_pos;
	uint32_t line_num;
};

struct message_header_line;

struct index_mail_data {
	time_t date, received_date, save_date;
	uoff_t virtual_size, physical_size;

	struct mail_sent_date sent_date;
	struct index_mail_line parse_line;
	uint32_t parse_line_num;

	struct message_part *parts;
	const char *envelope, *body, *bodystructure, *uid_string, *guid;
	struct message_part_envelope_data *envelope_data;

	uint32_t seq;
	uint32_t cache_flags;
	uint64_t modseq;
	enum index_mail_access_part access_part;
	/* dont_cache_fields overrides cache_fields */
	enum mail_fetch_field cache_fetch_fields, dont_cache_fetch_fields;
	unsigned int dont_cache_field_idx;

	struct istream *stream, *filter_stream;
	struct tee_istream *tee_stream;
	struct message_size hdr_size, body_size;
	struct message_parser_ctx *parser_ctx;
	int parsing_count;
	ARRAY_TYPE(keywords) keywords;
	ARRAY_TYPE(keyword_indexes) keyword_indexes;

	unsigned int save_sent_date:1;
	unsigned int sent_date_parsed:1;
	unsigned int save_envelope:1;
	unsigned int save_bodystructure_header:1;
	unsigned int save_bodystructure_body:1;
	unsigned int save_message_parts:1;
	unsigned int parsed_bodystructure:1;
	unsigned int hdr_size_set:1;
	unsigned int body_size_set:1;
	unsigned int messageparts_saved_to_cache:1;
	unsigned int header_parsed:1;
	unsigned int no_caching:1;
	unsigned int forced_no_caching:1;
	unsigned int destroying_stream:1;
	unsigned int initialized_wrapper_stream:1;
	unsigned int destroy_callback_set:1;
};

struct index_mail {
        struct mail_private mail;
	struct index_mail_data data;
	struct index_mailbox_context *ibox;

	pool_t data_pool;
	struct index_transaction_context *trans;
	uint32_t uid_validity;

	enum mail_fetch_field wanted_fields;
	struct index_header_lookup_ctx *wanted_headers;

	int pop3_state;

	/* per-mail variables, here for performance reasons: */
	uint32_t header_seq;
	string_t *header_data;
	ARRAY_DEFINE(header_lines, struct index_mail_line);
#define HEADER_MATCH_FLAG_FOUND 1
#define HEADER_MATCH_SKIP_COUNT 2
#define HEADER_MATCH_USABLE(mail, num) \
	((num & ~1) == (mail)->header_match_value)
	ARRAY_DEFINE(header_match, uint8_t);
	ARRAY_DEFINE(header_match_lines, unsigned int);
	uint8_t header_match_value;

	unsigned int pop3_state_set:1;
};

struct mail *
index_mail_alloc(struct mailbox_transaction_context *t,
		 enum mail_fetch_field wanted_fields,
		 struct mailbox_header_lookup_ctx *wanted_headers);
void index_mail_init(struct index_mail *mail,
		     struct mailbox_transaction_context *_t,
		     enum mail_fetch_field wanted_fields,
		     struct mailbox_header_lookup_ctx *_wanted_headers);

void index_mail_set_seq(struct mail *mail, uint32_t seq);
bool index_mail_set_uid(struct mail *mail, uint32_t uid);
void index_mail_set_uid_cache_updates(struct mail *mail, bool set);
void index_mail_close(struct mail *mail);
void index_mail_free(struct mail *mail);

bool index_mail_want_parse_headers(struct index_mail *mail);
void index_mail_parse_header_init(struct index_mail *mail,
				  struct mailbox_header_lookup_ctx *headers);
void index_mail_parse_header(struct message_part *part,
			     struct message_header_line *hdr,
			     struct index_mail *mail);
int index_mail_parse_headers(struct index_mail *mail,
			     struct mailbox_header_lookup_ctx *headers);
int index_mail_headers_get_envelope(struct index_mail *mail);

int index_mail_get_first_header(struct mail *_mail, const char *field,
				bool decode_to_utf8, const char **value_r);
int index_mail_get_headers(struct mail *_mail, const char *field,
			   bool decode_to_utf8, const char *const **value_r);
int index_mail_get_header_stream(struct mail *_mail,
				 struct mailbox_header_lookup_ctx *headers,
				 struct istream **stream_r);
void index_mail_set_read_buffer_size(struct mail *mail, struct istream *input);

enum mail_flags index_mail_get_flags(struct mail *_mail);
uint64_t index_mail_get_modseq(struct mail *_mail);
const char *const *index_mail_get_keywords(struct mail *_mail);
const ARRAY_TYPE(keyword_indexes) *
index_mail_get_keyword_indexes(struct mail *_mail);
int index_mail_get_parts(struct mail *_mail, struct message_part **parts_r);
int index_mail_get_received_date(struct mail *_mail, time_t *date_r);
int index_mail_get_save_date(struct mail *_mail, time_t *date_r);
int index_mail_get_date(struct mail *_mail, time_t *date_r, int *timezone_r);
int index_mail_get_virtual_size(struct mail *mail, uoff_t *size_r);
int index_mail_get_physical_size(struct mail *mail, uoff_t *size_r);
int index_mail_init_stream(struct index_mail *mail,
			   struct message_size *hdr_size,
			   struct message_size *body_size,
			   struct istream **stream_r);
int index_mail_get_special(struct mail *_mail, enum mail_fetch_field field,
			   const char **value_r);
struct mail *index_mail_get_real_mail(struct mail *mail);

void index_mail_update_flags(struct mail *mail, enum modify_type modify_type,
			     enum mail_flags flags);
void index_mail_update_keywords(struct mail *mail, enum modify_type modify_type,
				struct mail_keywords *keywords);
void index_mail_update_modseq(struct mail *mail, uint64_t min_modseq);
void index_mail_expunge(struct mail *mail);
void index_mail_parse(struct mail *mail, bool parse_body);
void index_mail_set_cache_corrupted(struct mail *mail,
				    enum mail_fetch_field field);
int index_mail_opened(struct mail *mail, struct istream **stream);
struct index_mail *index_mail_get_index_mail(struct mail *mail);

bool index_mail_get_cached_uoff_t(struct index_mail *mail,
				  enum index_cache_field field, uoff_t *size_r);
bool index_mail_get_cached_virtual_size(struct index_mail *mail,
					uoff_t *size_r);

void index_mail_cache_add(struct index_mail *mail, enum index_cache_field field,
			  const void *data, size_t data_size);
void index_mail_cache_add_idx(struct index_mail *mail, unsigned int field_idx,
			      const void *data, size_t data_size);

struct istream *index_mail_cache_parse_init(struct mail *mail,
					    struct istream *input);
void index_mail_cache_parse_continue(struct mail *mail);
void index_mail_cache_parse_deinit(struct mail *mail, time_t received_date,
				   bool success);

int index_mail_cache_lookup_field(struct index_mail *mail, buffer_t *buf,
				  unsigned int field_idx);

enum index_mail_access_part index_mail_get_access_part(struct index_mail *mail);

#endif
