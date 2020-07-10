#ifndef TEST_COMMON_H
#define TEST_COMMON_H

struct istream *test_istream_create(const char *data);
struct istream *test_istream_create_data(const void *data, size_t size);
void test_istream_set_size(struct istream *input, uoff_t size);
void test_istream_set_allow_eof(struct istream *input, bool allow);
void test_istream_set_max_buffer_size(struct istream *input, size_t size);

struct ostream *test_ostream_create(buffer_t *output);
struct ostream *test_ostream_create_nonblocking(buffer_t *output,
						size_t max_internal_buffer_size);
/* When output->used reaches max_size, start buffering output internally.
   When internal buffer reaches max_internal_buffer_size, start returning 0 for
   o_stream_send*(). */
void test_ostream_set_max_output_size(struct ostream *output, size_t max_size);

void test_begin(const char *name);
#define test_assert(code) STMT_START { \
	if (!(code)) test_assert_failed(#code, __FILE__, __LINE__); \
	} STMT_END
/* Additional parameter may be int or unsigned int, to indicate which of
 * a barrage of tests have failed (such as in a loop).
 */
#define test_assert_idx(code, i) STMT_START { \
		if (!(code)) test_assert_failed_idx(#code, __FILE__, __LINE__, i); \
	} STMT_END
/* Additional parameters are s1 (source) and s2 (destination) string
 * in strcmp().
 */
#define test_assert_strcmp(s1, s2) STMT_START { \
		test_assert_strcmp_idx(s1, s2, LLONG_MIN); \
	} STMT_END

/* Same as test_assert_strcmp expect that it takes an additional i as input.
 * When i is greater than or equals 0 it is used to identify the barrage of
 * tests failed like in test_assert_idx.
*/
#define test_assert_strcmp_idx(_s1, _s2, i) STMT_START { \
		const char *_temp_s1 = (_s1); \
		const char *_temp_s2 = (_s2); \
		if ((null_strcmp(_temp_s1,_temp_s2) != 0)) \
			test_assert_failed_strcmp_idx("strcmp(" #_s1 ","  #_s2 ")", \
						      __FILE__, __LINE__, _temp_s1, _temp_s2, i); \
	} STMT_END

void test_assert_failed(const char *code, const char *file, unsigned int line);
void test_assert_failed_idx(const char *code, const char *file, unsigned int line, long long i);
void test_assert_failed_strcmp_idx(const char *code, const char *file, unsigned int line,
				   const char * src, const char * dst, long long i);
bool test_has_failed(void);
/* If you're testing nasty cases which you want to warn, surround the noisy op with these */
void test_expect_errors(unsigned int expected);
void test_expect_error_string(const char *substr); /* expect just 1 message matching the printf format */
void test_expect_error_string_n_times(const char *substr, unsigned int times); /* expect just n messages matching the printf format */
void test_expect_no_more_errors(void);
/* Note that test_expect_error{s,_string}() effectively begin with a check equivalent
   to test_expect_no_more_errors(), so you don't need the latter explicitly if following
   it with either of the former.*/

void test_end(void);

void test_out(const char *name, bool success);
void test_out_quiet(const char *name, bool success); /* only prints failures */
void test_out_reason(const char *name, bool success, const char *reason)
	ATTR_NULL(3);

int test_run(void (*const test_functions[])(void)) ATTR_WARN_UNUSED_RESULT;
struct named_test {
	const char *name;
	void (*func)(void);
};
int test_run_named(const struct named_test tests[], const char *match) ATTR_WARN_UNUSED_RESULT;

#define TEST_DECL(x) void x(void);
#define TEST_NAMELESS(x) x, /* Were you to want to use the X trick but not name the tests */
#define TEST_NAMED(x) { .name = #x , .func = x },

enum fatal_test_state {
	FATAL_TEST_FINISHED, /* no more test stages, don't call again */
	FATAL_TEST_FAILURE,  /* single stage has failed, continue */
	FATAL_TEST_ABORT,    /* something's gone horrifically wrong */
};
/* The fatal function is called first with stage=0. After each call the stage
   is increased by 1. The idea is that each stage would be running an
   individual test that is supposed to crash. The function is called until
   FATAL_TEST_FINISHED or FATAL_TEST_ABORT is returned. */
typedef enum fatal_test_state test_fatal_func_t(unsigned int stage);

struct named_fatal {
	const char *name;
	test_fatal_func_t *func;
};
int test_run_with_fatals(void (*const test_functions[])(void),
			 test_fatal_func_t *const fatal_functions[]);
int test_run_named_with_fatals(const char *match, const struct named_test tests[],
			       const struct named_fatal fatals[]);

/* Require the Fatal/Panic string to match this or the fatal test fails. */
void test_expect_fatal_string(const char *substr);

#define FATAL_DECL(x) enum fatal_test_state x(unsigned int);
#define FATAL_NAMELESS(x) x, /* Were you to want to use the X trick but not name the tests */
#define FATAL_NAMED(x) { .name = #x , .func = x },

/* If a fork() wants to exit(), then this will avoid valgrind leak errors */
void test_exit(int status) ATTR_NORETURN;

#endif
