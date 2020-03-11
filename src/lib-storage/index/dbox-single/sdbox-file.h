#ifndef SDBOX_FILE_H
#define SDBOX_FILE_H

#include "dbox-file.h"

struct sdbox_file {
	struct dbox_file file;
	struct sdbox_mailbox *mbox;

	/* 0 while file is being created */
	uint32_t uid;

	/* list of attachment paths while saving/copying message */
	pool_t attachment_pool;
	ARRAY_TYPE(const_string) attachment_paths;
	bool written_to_disk;
};

struct dbox_file *sdbox_file_init(struct sdbox_mailbox *mbox, uint32_t uid);
struct dbox_file *sdbox_file_create(struct sdbox_mailbox *mbox);
void sdbox_file_free(struct dbox_file *file);

/* Get file's extrefs metadata. */
int sdbox_file_get_attachments(struct dbox_file *file, const char **extrefs_r);
/* Returns attachment path for this file, given the source path. The result is
   always <hash>-<guid>-<mailbox_guid>-<uid>. The source path is expected to
   contain <hash>-<guid>[-*]. */
const char *
sdbox_file_attachment_relpath(struct sdbox_file *file, const char *srcpath);

/* Assign UID for a newly created file (by renaming it) */
int sdbox_file_assign_uid(struct sdbox_file *file, uint32_t uid);

int sdbox_file_create_fd(struct dbox_file *file, const char *path,
			 bool parents);
/* Move the file to alt path or back. */
int sdbox_file_move(struct dbox_file *file, bool alt_path);
/* Unlink file and all of its referenced attachments. */
int sdbox_file_unlink_with_attachments(struct sdbox_file *sfile);
/* Unlink file and its attachments when rolling back a saved message. */
int sdbox_file_unlink_aborted_save(struct sdbox_file *file);

#endif
