#ifndef MDBOX_MAP_PRIVATE_H
#define MDBOX_MAP_PRIVATE_H

#include "mdbox-map.h"

struct dbox_mail_lookup_rec {
	uint32_t map_uid;
	uint16_t refcount;
	struct mdbox_map_mail_index_record rec;
};

struct mdbox_map {
	struct mdbox_storage *storage;
	const struct mdbox_settings *set;
	char *path, *index_path;

	struct mail_index *index;
	struct mail_index_view *view;

	uint32_t map_ext_id, ref_ext_id;

	struct mailbox_list *root_list;

	unsigned int verify_existing_file_ids:1;
};

struct mdbox_map_append {
	struct dbox_file_append_context *file_append;
	uoff_t offset, size;
};

struct mdbox_map_append_context {
	struct mdbox_map *map;
	struct mdbox_map_atomic_context *atomic;
	struct mail_index_transaction *trans;

	ARRAY(struct dbox_file_append_context *) file_appends;
	ARRAY(struct dbox_file *) files;
	ARRAY(struct mdbox_map_append) appends;

	uint32_t first_new_file_id;

	unsigned int files_nonappendable_count;

	unsigned int failed:1;
};

struct mdbox_map_atomic_context {
	struct mdbox_map *map;
	struct mail_index_transaction *sync_trans;
	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *sync_view;

	unsigned int map_refreshed:1;
	unsigned int locked:1;
	unsigned int success:1;
	unsigned int failed:1;
};

int mdbox_map_view_lookup_rec(struct mdbox_map *map,
			      struct mail_index_view *view, uint32_t seq,
			      struct dbox_mail_lookup_rec *rec_r);

#endif
