#ifndef TEST_COMMON_H
#define TEST_COMMON_H

struct istream *test_istream_create(const char *data);

void test_out(const char *name, bool success);

void test_init(void);
int test_deinit(void);

#endif
