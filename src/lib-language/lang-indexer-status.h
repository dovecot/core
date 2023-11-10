#ifndef LANG_INDEXER_STATUS_H
#define LANG_INDEXER_STATUS_H

enum indexer_state {
	INDEXER_STATE_PROCESSING =  0,
	INDEXER_STATE_COMPLETED  =  1,
	INDEXER_STATE_FAILED     = -1,
};

struct indexer_status {
	enum indexer_state state;
	unsigned int progress;
	unsigned int total;
};

#endif
