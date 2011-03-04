/* Copyright (c) 2007-2011 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

int main(void)
{
	static void (*test_functions[])(void) = {
		test_aqueue,
		test_array,
		test_base64,
		test_bsearch_insert_pos,
		test_buffer,
		test_crc32,
		test_hash_format,
		test_hex_binary,
		test_istream_base64_encoder,
		test_istream_concat,
		test_istream_crlf,
		test_istream_seekable,
		test_istream_tee,
		test_llist,
		test_mempool_alloconly,
		test_network,
		test_ostream_file,
		test_primes,
		test_priorityq,
		test_seq_range_array,
		test_strescape,
		test_strfuncs,
		test_str_find,
		test_str_sanitize,
		test_time_util,
		test_utc_mktime,
		test_var_expand,
		NULL
	};
	return test_run(test_functions);
}
