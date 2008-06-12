#ifndef TEST_COMMON_H
#define TEST_COMMON_H

struct istream *test_istream_create(const char *data);
void test_istream_set_size(struct istream *input, uoff_t size);
void test_istream_set_allow_eof(struct istream *input, bool allow);

void test_out(const char *name, bool success);
void test_out_reason(const char *name, bool success, const char *reason);

void test_init(void);
int test_deinit(void);

#endif
