#ifndef DSYNC_MAILBOX_STATE_H
#define DSYNC_MAILBOX_STATE_H

#include "guid.h"

struct dsync_mailbox_state {
	guid_128_t mailbox_guid;
	uint32_t last_uidvalidity;
	uint32_t last_common_uid;
	uint64_t last_common_modseq;
};
ARRAY_DEFINE_TYPE(dsync_mailbox_state, struct dsync_mailbox_state);

void dsync_mailbox_states_export(const struct dsync_mailbox_state *states,
				 unsigned int states_count, string_t *output);
int dsync_mailbox_states_import(ARRAY_TYPE(dsync_mailbox_state) *states,
				const char *input, const char **error_r);

#endif
