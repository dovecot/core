#ifndef INDEXER_H
#define INDEXER_H

/* percentage: -1 = failed, 0..99 = indexing in progress, 100 = done */
typedef void indexer_status_callback_t(int percentage, void *context);

void indexer_refresh_proctitle(void);

#endif
