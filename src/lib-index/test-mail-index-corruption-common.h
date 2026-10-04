#ifndef TEST_MAIL_INDEX_CORRUPTION_COMMON_H
#define TEST_MAIL_INDEX_CORRUPTION_COMMON_H

#include "mail-index.h"

#define TEST_INDEX_PREFIX "test.dovecot.index"

struct test_index_file {
	char *name;
	unsigned char *data;
	size_t size;
};
ARRAY_DEFINE_TYPE(test_index_file, struct test_index_file);

/* Files read by test_index_files_read() */
extern ARRAY_TYPE(test_index_file) test_index_files;

/* Create an index to the given directory with all kinds of changes in the
   dovecot.index, .log, .log.2 and .cache files. */
void test_index_create(const char *dir);
/* Read all the index files into test_index_files. */
void test_index_files_read(void);
/* Free test_index_files and the directory set by test_index_create(). */
void test_index_files_free(void);

/* Write the index files, with corrupted_file's contents replaced with data.
   Then open the index and do lookups, syncs and updates. *success_r is set
   to FALSE if opening the index failed. */
void test_index_corrupted_open(const struct test_index_file *corrupted_file,
			       const unsigned char *data, size_t size,
			       enum mail_index_open_flags open_flags,
			       bool *success_r);

#endif
