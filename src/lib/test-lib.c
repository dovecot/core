/* Copyright (c) 2007-2016 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

int main(void)
{
	static void (*test_functions[])(void) = {
		test_aqueue,
		test_array,
		test_base32,
		test_base64,
		test_bits,
		test_bsearch_insert_pos,
		test_buffer,
		test_crc32,
		test_data_stack,
		test_failures,
		test_guid,
		test_hash,
		test_hash_format,
		test_hash_method,
		test_hex_binary,
		test_ioloop,
		test_iso8601_date,
		test_iostream_temp,
		test_istream,
		test_istream_base64_decoder,
		test_istream_base64_encoder,
		test_istream_chain,
		test_istream_concat,
		test_istream_crlf,
		test_istream_failure_at,
		test_istream_seekable,
		test_istream_tee,
		test_istream_unix,
		test_json_parser,
		test_json_tree,
		test_llist,
		test_mempool_alloconly,
		test_net,
		test_numpack,
		test_pkcs5_pbkdf2,
		test_ostream_escaped,
		test_ostream_failure_at,
		test_ostream_file,
		test_primes,
		test_printf_format_fix,
		test_priorityq,
		test_seq_range_array,
		test_str,
		test_strescape,
		test_strfuncs,
		test_strnum,
		test_str_find,
		test_str_sanitize,
		test_str_table,
		test_time_util,
		test_timing,
		test_unichar,
		test_utc_mktime,
		test_var_expand,
		test_wildcard_match,
		NULL
	};
	static enum fatal_test_state (*fatal_functions[])(int) = {
		fatal_array,
		fatal_data_stack,
		fatal_mempool,
		fatal_printf_format_fix,
		NULL
	};
	return test_run_with_fatals(test_functions, fatal_functions);
}
