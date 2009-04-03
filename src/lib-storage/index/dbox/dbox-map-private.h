#ifndef DBOX_MAP_PRIVATE_H
#define DBOX_MAP_PRIVATE_H

#include "dbox-map.h"

struct dbox_mail_lookup_rec {
	uint32_t map_uid;
	uint16_t refcount;
	struct dbox_mail_index_map_record rec;
};

struct dbox_map {
	struct dbox_storage *storage;
	struct mail_index *index;
	struct mail_index_view *view;
	uint32_t created_uid_validity;

	uint32_t map_ext_id, ref_ext_id;
	ARRAY_TYPE(seq_range) ref0_file_ids;
};

struct dbox_map_append {
	struct dbox_file *file;
	uoff_t offset, size;
};

struct dbox_map_append_context {
	struct dbox_mailbox *mbox;
	struct dbox_map *map;

	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *sync_trans, *trans;

	ARRAY_DEFINE(files, struct dbox_file *);
	ARRAY_DEFINE(appends, struct dbox_map_append);

	uint32_t first_new_file_id;
	uint32_t orig_next_uid;

	unsigned int files_nonappendable_count;

	unsigned int failed:1;
	unsigned int committed:1;
};

int dbox_map_view_lookup_rec(struct dbox_map *map, struct mail_index_view *view,
			     uint32_t seq, struct dbox_mail_lookup_rec *rec_r);

#endif
