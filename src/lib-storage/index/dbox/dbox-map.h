#ifndef DBOX_MAP_H
#define DBOX_MAP_H

struct dbox_storage;
struct dbox_file;
struct dbox_map_append_context;

struct dbox_map *dbox_map_init(struct dbox_storage *storage);
void dbox_map_deinit(struct dbox_map **map);

int dbox_map_lookup(struct dbox_map *map, uint32_t map_uid,
		    uint32_t *file_id_r, uoff_t *offset_r);

struct dbox_map_append_context *
dbox_map_append_begin(struct dbox_mailbox *mbox);
/* Request file for saving a new message with given size (if available). If an
   existing file can be used, the record is locked and updated in index.
   Returns 0 if ok, -1 if error. */
int dbox_map_append_next(struct dbox_map_append_context *ctx, uoff_t mail_size,
			 struct dbox_file **file_r, struct ostream **output_r);
/* Finished saving the last mail. Saves the message size. */
void dbox_map_append_finish_multi_mail(struct dbox_map_append_context *ctx);
/* Assign map UIDs to all appended msgs to multi-files. */
int dbox_map_append_assign_map_uids(struct dbox_map_append_context *ctx,
				    uint32_t *first_map_uid_r,
				    uint32_t *last_map_uid_r);
/* Assign UIDs to all created single-files. */
int dbox_map_append_assign_uids(struct dbox_map_append_context *ctx,
				uint32_t first_uid, uint32_t last_uid);
/* Returns 0 if ok, -1 if error. */
void dbox_map_append_commit(struct dbox_map_append_context **ctx);
void dbox_map_append_rollback(struct dbox_map_append_context **ctx);

#endif
