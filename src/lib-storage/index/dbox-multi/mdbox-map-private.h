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
	mode_t create_mode;
	gid_t create_gid;
	const char *create_gid_origin;
};

struct mdbox_map_append {
	struct dbox_file_append_context *file_append;
	uoff_t offset, size;
};

struct mdbox_map_append_context {
	struct mdbox_map *map;
	struct mdbox_map_atomic_context *atomic;
	struct mail_index_transaction *trans;

	ARRAY_DEFINE(file_appends, struct dbox_file_append_context *);
	ARRAY_DEFINE(files, struct dbox_file *);
	ARRAY_DEFINE(appends, struct mdbox_map_append);

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
};

int mdbox_map_view_lookup_rec(struct mdbox_map *map,
			      struct mail_index_view *view, uint32_t seq,
			      struct dbox_mail_lookup_rec *rec_r);

#endif
