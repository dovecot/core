#ifndef MDBOX_FILE_H
#define MDBOX_FILE_H

#include "dbox-file.h"

struct mdbox_file {
	struct dbox_file file;
	struct mdbox_storage *storage;

	uint32_t file_id;
	time_t close_time;
};

struct dbox_file *
mdbox_file_init(struct mdbox_storage *storage, uint32_t file_id);
struct dbox_file *
mdbox_file_init_new_alt(struct mdbox_storage *storage);

/* Assign file ID for a newly created file. */
int mdbox_file_assign_file_id(struct mdbox_file *file, uint32_t file_id);

void mdbox_file_unrefed(struct dbox_file *file);
int mdbox_file_create_fd(struct dbox_file *file, const char *path,
			 bool parents);

void mdbox_files_free(struct mdbox_storage *storage);
void mdbox_files_sync_input(struct mdbox_storage *storage);

#endif
