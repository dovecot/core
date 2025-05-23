#ifndef RAW_STORAGE_H
#define RAW_STORAGE_H

#include "index-storage.h"

struct setting_parser_context;
struct settings_instance;
struct mail_storage_service_ctx;

#define RAW_STORAGE_NAME "raw"

struct raw_storage {
	struct mail_storage storage;
};

struct raw_mailbox {
	struct mailbox box;
	struct raw_storage *storage;

	time_t mtime, ctime;
	uoff_t size;
	const char *envelope_sender;

	bool synced:1;
	bool have_filename:1;
};

#define RAW_STORAGE(s)		container_of(s, struct raw_storage, storage)
#define RAW_MAILBOX(s)		container_of(s, struct raw_mailbox, box)

extern struct mail_vfuncs raw_mail_vfuncs;

struct mail_user *
raw_storage_create_from_set(struct mail_storage_service_ctx *ctx,
			    struct settings_instance *set_instance);

int raw_mailbox_alloc_stream(struct mail_user *user, struct istream *input,
			     time_t received_time, const char *envelope_sender,
			     struct mailbox **box_r);
int raw_mailbox_alloc_path(struct mail_user *user, const char *path,
			   time_t received_time, const char *envelope_sender,
			   struct mailbox **box_r);

#endif
