#ifndef __INDEX_FETCH_H
#define __INDEX_FETCH_H

typedef struct {
	Mailbox *box;
	MailStorage *storage;
	ImapMessageCache *cache;
	MailIndex *index;

	const char **custom_flags;
	unsigned int custom_flags_count;

	MailFetchData *fetch_data;
	OStream *output;
	TempString *str;
	int update_seen, failed;
	int first;
} FetchContext;

ImapCacheField index_fetch_body_get_cache(const char *section);
int index_fetch_body_section(MailIndexRecord *rec, MailFetchBodyData *sect,
			     FetchContext *ctx);

#endif
