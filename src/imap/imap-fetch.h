#ifndef __IMAP_FETCH_H
#define __IMAP_FETCH_H

enum imap_fetch_field {
	IMAP_FETCH_UID			= 0x01,
	IMAP_FETCH_RFC822		= 0x02,
	IMAP_FETCH_RFC822_HEADER	= 0x04,
	IMAP_FETCH_RFC822_TEXT		= 0x08
};

struct imap_fetch_body_data {
	struct imap_fetch_body_data *next;

	const char *section; /* NOTE: always uppercased */
	uoff_t skip, max_size; /* if you don't want max_size,
	                          set it to (uoff_t)-1 */
	unsigned int skip_set:1;
	unsigned int peek:1;
};

struct imap_fetch_context {
	struct mail_search_context *search_ctx;

	enum mail_fetch_field fetch_data;
	enum imap_fetch_field imap_data;
	struct imap_fetch_body_data *bodies;

	string_t *str;
	struct ostream *output;
	const char *prefix;
	unsigned int select_counter;

	int update_seen;
	struct mail_full_flags seen_flag;

	int first, failed, body_fetch_from_cache;
};

int imap_fetch(struct client *client,
	       enum mail_fetch_field fetch_data,
	       enum imap_fetch_field imap_data,
	       struct imap_fetch_body_data *bodies,
	       const char *messageset, int uidset);

int imap_fetch_body_section(struct imap_fetch_context *ctx,
			    const struct imap_fetch_body_data *body,
			    struct mail *mail);

const char *const *imap_fetch_get_body_fields(const char *fields);

#endif
