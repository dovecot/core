#ifndef __INDEX_FETCH_H
#define __INDEX_FETCH_H

typedef struct {
	Mailbox *box;
	MailStorage *storage;
	ImapMessageCache *cache;
	MailIndex *index;
	const char **custom_flags;

	MailFetchData *fetch_data;
	IOBuffer *outbuf;
	TempString *str;
	int update_seen, found_unseen;
	int first;
} FetchContext;

ImapCacheField index_fetch_body_get_cache(const char *section);
int index_fetch_body_section(MailIndexRecord *rec, MailFetchBodyData *sect,
			     FetchContext *ctx);

#endif
