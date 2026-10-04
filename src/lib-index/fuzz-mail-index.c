/* Copyright (c) Dovecot authors, see top-level COPYING file */

#include "lib.h"
#include "array.h"
#include "write-full.h"
#include "unlink-directory.h"
#include "fuzzer.h"
#include "test-mail-index-corruption-common.h"

#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>

/* The input's first byte selects the index file that is replaced with the
   rest of the input, and how the index is opened. The other index files are
   kept valid. Set FUZZ_MAIL_INDEX_CORPUS_DIR environment to write the valid
   index files as a seed corpus to the directory. */
static const enum mail_index_open_flags fuzz_open_flags[] = {
	0,
	MAIL_INDEX_OPEN_FLAG_MMAP_DISABLE,
	MAIL_INDEX_OPEN_FLAG_SAVEONLY,
};

static char *fuzz_dir = NULL;

static void
fuzz_ignore_logs(const struct failure_context *ctx ATTR_UNUSED,
		 const char *format ATTR_UNUSED, va_list args ATTR_UNUSED)
{
	/* Corruption is expected to be logged as errors and warnings */
}

/* Write the uncorrupted index files as seed corpus files */
static void fuzz_mail_index_write_corpus(const char *dir)
{
	const struct test_index_file *files;
	unsigned int count, i, j;

	files = array_get(&test_index_files, &count);
	for (i = 0; i < count; i++) {
		for (j = 0; j < N_ELEMENTS(fuzz_open_flags); j++) {
			const char *path = t_strdup_printf("%s/%s-%u", dir,
							   files[i].name, j);
			unsigned char selector = i + j * count;
			int fd = creat(path, 0600);
			if (fd == -1)
				i_fatal("creat(%s) failed: %m", path);
			if (write_full(fd, &selector, 1) < 0 ||
			    write_full(fd, files[i].data, files[i].size) < 0)
				i_fatal("write(%s) failed: %m", path);
			i_close_fd(&fd);
		}
	}
}

static void fuzz_mail_index_deinit(void)
{
	const char *error;

	(void)unlink_directory(fuzz_dir, UNLINK_DIRECTORY_FLAG_RMDIR, &error);
	i_free(fuzz_dir);
}

static void fuzz_mail_index_init(void)
{
	const char *corpus_dir, *tmpdir;

	if (fuzz_dir != NULL)
		return;
	tmpdir = getenv("TMPDIR");
	if (tmpdir == NULL || tmpdir[0] == '\0')
		tmpdir = "/tmp";
	fuzz_dir = i_strdup_printf("%s/fuzz-mail-index.XXXXXX", tmpdir);
	if (mkdtemp(fuzz_dir) == NULL)
		i_fatal("mkdtemp(%s) failed: %m", fuzz_dir);
	atexit(fuzz_mail_index_deinit);
	test_index_create(t_strconcat(fuzz_dir, "/index", NULL));
	test_index_files_read();
	i_assert(array_count(&test_index_files) > 0);
	corpus_dir = getenv("FUZZ_MAIL_INDEX_CORPUS_DIR");
	if (corpus_dir != NULL)
		fuzz_mail_index_write_corpus(corpus_dir);
}

int LLVMFuzzerInitialize(int *argc, char ***argv);
int LLVMFuzzerInitialize(int *argc ATTR_UNUSED, char ***argv ATTR_UNUSED)
{
	/* Keep lib initialized between the runs. lib-index registers event
	   categories that must not be freed by lib_deinit(). */
	lib_init();
	return 0;
}

FUZZ_BEGIN_DATA(const uint8_t *data, size_t size)
{
	const struct test_index_file *files, *file;
	unsigned int count, i;
	bool success;

	i_set_error_handler(fuzz_ignore_logs);
	i_set_info_handler(fuzz_ignore_logs);
	fuzz_mail_index_init();

	if (size > 0) {
		files = array_get(&test_index_files, &count);
		file = &files[data[0] % count];
		i = (data[0] / count) % N_ELEMENTS(fuzz_open_flags);

		test_index_corrupted_open(file, data + 1, size - 1,
					  fuzz_open_flags[i], &success);
	}
}
FUZZ_END
