#ifndef TEST_LIB
#define TEST_LIB

#include "lib.h"
#include "test-common.h"

void test_aqueue(void);
void test_array(void);
void test_base64(void);
void test_bsearch_insert_pos(void);
void test_buffer(void);
void test_crc32(void);
void test_hash_format(void);
void test_hex_binary(void);
void test_istream_base64_encoder(void);
void test_istream_concat(void);
void test_istream_crlf(void);
void test_istream_seekable(void);
void test_istream_tee(void);
void test_llist(void);
void test_mempool_alloconly(void);
void test_network(void);
void test_ostream_file(void);
void test_primes(void);
void test_priorityq(void);
void test_seq_range_array(void);
void test_strescape(void);
void test_strfuncs(void);
void test_str_find(void);
void test_str_sanitize(void);
void test_time_util(void);
void test_utc_mktime(void);
void test_var_expand(void);

#endif
