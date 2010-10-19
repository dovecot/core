#ifndef FS_API_PRIVATE_H
#define FS_API_PRIVATE_H

#include "fs-api.h"

struct fs_vfuncs {
	struct fs *(*init)(const char *args, const struct fs_settings *set);
	void (*deinit)(struct fs *fs);

	int (*open)(struct fs *fs, const char *path, enum fs_open_mode mode,
		    enum fs_open_flags flags, struct fs_file **file_r);
	void (*close)(struct fs_file *file);

	ssize_t (*read)(struct fs_file *file, void *buf, size_t size);
	struct istream *(*read_stream)(struct fs_file *file,
				       size_t max_buffer_size);

	int (*write)(struct fs_file *file, const void *data, size_t size);
	void (*write_stream)(struct fs_file *file);
	int (*write_stream_finish)(struct fs_file *file, bool success);

	int (*lock)(struct fs_file *file, unsigned int secs,
		    struct fs_lock **lock_r);
	void (*unlock)(struct fs_lock *lock);
	int (*fdatasync)(struct fs_file *file);

	int (*exists)(struct fs *fs, const char *path);
	int (*stat)(struct fs *fs, const char *path, struct stat *st_r);
	int (*link)(struct fs *fs, const char *src, const char *dest);
	int (*rename)(struct fs *fs, const char *src, const char *dest);
	int (*unlink)(struct fs *fs, const char *path);
	int (*rmdir)(struct fs *fs, const char *path);
};

struct fs {
	const char *name;
	struct fs_vfuncs v;

	struct fs_settings set;
	string_t *last_error;

	unsigned int files_open_count;
};

struct fs_file {
	struct fs *fs;
	struct ostream *output;
	char *path;
};

struct fs_lock {
	struct fs_file *file;
};

extern struct fs fs_class_posix;
extern struct fs fs_class_sis;
extern struct fs fs_class_sis_queue;

void fs_set_error(struct fs *fs, const char *fmt, ...) ATTR_FORMAT(2, 3);
void fs_set_critical(struct fs *fs, const char *fmt, ...) ATTR_FORMAT(2, 3);

#endif
