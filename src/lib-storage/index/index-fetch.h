#ifndef __INDEX_FETCH_H
#define __INDEX_FETCH_H

typedef struct {
	Mailbox *box;
	ImapMessageCache *cache;
	MailIndex *index;
	const char **custom_flags;

	MailFetchData *fetch_data;
	IOBuffer *outbuf;
	TempString *str;
	int update_seen;
	int first;
} FetchContext;

ImapCacheField index_fetch_body_get_cache(const char *section);
void index_fetch_body_section(MailIndexRecord *rec, unsigned int seq,
			      MailFetchBodyData *sect, FetchContext *data);

#endif
