#ifndef IMAP_MESSAGESET_H
#define IMAP_MESSAGESET_H

struct mail_search_seqset *
imap_messageset_parse(pool_t pool, const char *messageset);

#endif
