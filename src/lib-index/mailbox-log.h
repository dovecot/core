#ifndef MAILBOX_LOG_H
#define MAILBOX_LOG_H

#include "guid.h"

enum mailbox_log_record_type {
	MAILBOX_LOG_RECORD_DELETE_MAILBOX = 1,
	MAILBOX_LOG_RECORD_DELETE_DIR,
	MAILBOX_LOG_RECORD_RENAME,
	MAILBOX_LOG_RECORD_SUBSCRIBE,
	MAILBOX_LOG_RECORD_UNSUBSCRIBE,
	MAILBOX_LOG_RECORD_CREATE_DIR
};

struct mailbox_log_record {
	uint8_t type;
	uint8_t padding[3];
	guid_128_t mailbox_guid;
	uint8_t timestamp[4];
};

struct mailbox_log *
mailbox_log_alloc(struct event *parent_event, const char *path);
void mailbox_log_free(struct mailbox_log **log);

void mailbox_log_set_permissions(struct mailbox_log *log, mode_t mode,
				 gid_t gid, const char *gid_origin);

void mailbox_log_record_set_timestamp(struct mailbox_log_record *rec,
				      time_t stamp);
time_t mailbox_log_record_get_timestamp(const struct mailbox_log_record *rec);

/* Append a new record to mailbox log. Returns 0 if ok, -1 if error. */
int mailbox_log_append(struct mailbox_log *log,
		       const struct mailbox_log_record *rec);

/* Iterate through all records in mailbox log. */
struct mailbox_log_iter *mailbox_log_iter_init(struct mailbox_log *log);
const struct mailbox_log_record *
mailbox_log_iter_next(struct mailbox_log_iter *iter);
/* Returns 0 if ok, -1 if I/O error. */
int mailbox_log_iter_deinit(struct mailbox_log_iter **iter);

#endif
