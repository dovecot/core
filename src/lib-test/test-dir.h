#ifndef TEST_DIR_H
#define TEST_DIR_H

void test_dir_init(const char *top_test_dir, const char *name);
#define test_dir_init(name) test_dir_init(TEST_DIR, name);

const char *test_dir_get(void);
const char *test_dir_get_prefix(void);
const char *test_dir_prepend(const char *path);

#endif
