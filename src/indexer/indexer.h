#ifndef INDEXER_H
#define INDEXER_H

struct indexer_request;

/* percentage: -1 = failed, 0..99 = indexing in progress, 100 = done */
typedef void
indexer_status_callback_t(int percentage, struct indexer_request *request);

void indexer_refresh_proctitle(void);

#endif
