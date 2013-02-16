#ifndef DSYNC_MAILBOX_STATE_H
#define DSYNC_MAILBOX_STATE_H

#include "guid.h"

struct dsync_mailbox_state {
	guid_128_t mailbox_guid;
	uint32_t last_uidvalidity;
	uint32_t last_common_uid;
	uint64_t last_common_modseq;
	uint64_t last_common_pvt_modseq;
	bool changes_during_sync;
};
ARRAY_DEFINE_TYPE(dsync_mailbox_state, struct dsync_mailbox_state);
HASH_TABLE_DEFINE_TYPE(dsync_mailbox_state, uint8_t *, struct dsync_mailbox_state *);

void dsync_mailbox_states_export(const HASH_TABLE_TYPE(dsync_mailbox_state) states,
				 string_t *output);
int dsync_mailbox_states_import(HASH_TABLE_TYPE(dsync_mailbox_state) states,
				pool_t pool, const char *input,
				const char **error_r);

#endif
