#ifndef INDEXER_H
#define INDEXER_H

#include "fts-indexer-status.h"

struct indexer_request;

typedef void
indexer_status_callback_t(const struct indexer_status *status,
                          struct indexer_request *request);

void indexer_refresh_proctitle(void);

#endif
