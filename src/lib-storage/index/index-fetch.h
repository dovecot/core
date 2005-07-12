#ifndef __INDEX_FETCH_H
#define __INDEX_FETCH_H

struct fetch_context {
	struct mailbox *box;
	struct mail_storage *storage;
	struct imap_message_cache *cache;
	struct mail_index *index;

	const char **keywords;
	unsigned int keywords_count;

	struct ostream *output;
	string_t *str;
	int update_seen, failed;
	int first;
};

enum imap_cache_field index_fetch_body_get_cache(const char *section);
int index_fetch_body_section(struct mail_index_record *rec,
			     struct mail_fetch_body_data *sect,
			     struct fetch_context *ctx);

#endif
