#ifndef MDBOX_MAP_PRIVATE_H
#define MDBOX_MAP_PRIVATE_H

#include "mdbox-map.h"

struct dbox_mail_lookup_rec {
	uint32_t map_uid;
	uint16_t refcount;
	struct dbox_map_mail_index_record rec;
};

struct dbox_map {
	struct mdbox_storage *storage;
	const struct mdbox_settings *set;
	char *path;

	struct mail_index *index;
	struct mail_index_view *view;
	uint32_t created_uid_validity;

	uint32_t map_ext_id, ref_ext_id;

	mode_t create_mode, create_dir_mode;
	gid_t create_gid;
	const char *create_gid_origin;
};

struct dbox_map_append {
	struct dbox_file_append_context *file_append;
	uoff_t offset, size;
};

struct dbox_map_append_context {
	struct dbox_map *map;

	struct mail_index_sync_ctx *sync_ctx;
	struct mail_index_view *sync_view;
	struct mail_index_transaction *sync_trans, *trans;

	ARRAY_DEFINE(file_appends, struct dbox_file_append_context *);
	ARRAY_DEFINE(files, struct dbox_file *);
	ARRAY_DEFINE(appends, struct dbox_map_append);

	uint32_t first_new_file_id;

	unsigned int files_nonappendable_count;

	unsigned int failed:1;
	unsigned int committed:1;
};

int dbox_map_view_lookup_rec(struct dbox_map *map, struct mail_index_view *view,
			     uint32_t seq, struct dbox_mail_lookup_rec *rec_r);

#endif
