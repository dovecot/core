#ifndef DBOX_INDEX_H
#define DBOX_INDEX_H

struct dbox_file;
struct dbox_index_append_context;

struct dbox_index *dbox_index_init(struct dbox_mailbox *mbox);
void dbox_index_deinit(struct dbox_index **index);

struct dbox_index_append_context *
dbox_index_append_begin(struct dbox_index *index);
/* Request file for saving a new message with given size. If an existing file
   can be used, the record is locked and updated in index. Returns 0 if ok,
   -1 if error. */
int dbox_index_append_next(struct dbox_index_append_context *ctx,
			   uoff_t mail_size,
			   struct dbox_file **file_r,
			   struct ostream **output_r);
/* Assign file_ids to all appended files. */
int dbox_index_append_assign_file_ids(struct dbox_index_append_context *ctx);
/* Returns 0 if ok, -1 if error. */
int dbox_index_append_commit(struct dbox_index_append_context **ctx);
void dbox_index_append_rollback(struct dbox_index_append_context **ctx);

#endif
