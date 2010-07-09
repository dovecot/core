#ifndef SDBOX_FILE_H
#define SDBOX_FILE_H

#include "dbox-file.h"

struct sdbox_file {
	struct dbox_file file;
	struct sdbox_mailbox *mbox;

	/* 0 while file is being created */
	uint32_t uid;
};

struct dbox_file *sdbox_file_init(struct sdbox_mailbox *mbox, uint32_t uid);
struct dbox_file *sdbox_file_create(struct sdbox_mailbox *mbox);

/* Assign UID for a newly created file (by renaming it) */
int sdbox_file_assign_uid(struct sdbox_file *file, uint32_t uid);

int sdbox_file_create_fd(struct dbox_file *file, const char *path,
			 bool parents);
/* Move the file to alt path or back. */
int sdbox_file_move(struct dbox_file *file, bool alt_path);

#endif
