/* Copyright (c) 2014-2017 Dovecot authors, see the included COPYING file */

#include "test-lib.h"


#define INVALID(n) { #n, -1, 0 }
#define VALID(n) { #n, 0, n }

/* always pads with leading zeros to a size of 9 digits */
static int crappy_uintmax_to_str(char *into, uintmax_t val)
{
#define BIGBASE 1000000000ull
#define STRINGIFY(s) #s
#define STRINGIFY2(s) STRINGIFY(s)
	int len = 0;
	if(val >= BIGBASE) {
		len = crappy_uintmax_to_str(into, val/BIGBASE);
	}
	i_snprintf(into + len, 10, "%09llu",
		(unsigned long long)(val % BIGBASE));
	return len + strlen(STRINGIFY2(BIGBASE))-4;
#undef STRINGIFY2
#undef STRINGIFY
#undef BIGBASE
}
static void test_str_to_uintmax(void)
{
	unsigned int i=0;
	int randrange = rand()%15+1; /* when 1, will max out on 1s */
	uintmax_t value = 0, valbase = rand() * 1000ull;
	int len, ret;
	char buff[50]; /* totally assumes < 159 bits */

	test_begin("str_to_uintmax in range");
	while (i < sizeof(uintmax_t)*CHAR_BIT) {
		uintmax_t value_back;
		const char *endp;

		value = (value << 1) + 1;
		if (value >= 64)
			value -= rand()%randrange; /* don't always test the same numbers */
		len = crappy_uintmax_to_str(buff, value);
		ret = str_to_uintmax(buff, &value_back);
		test_assert_idx(ret == 0, i);
		test_assert_idx(value == value_back, i);

		/* test with trailing noise */
		buff[len] = 'x'; /* don't even null-terminate, let's be evil */
		value_back = 0x1234567890123456;
		ret = str_to_uintmax(buff, &value_back);
		test_assert_idx(ret < 0, i);
		test_assert_idx(value_back == 0x1234567890123456, i);
		ret = str_parse_uintmax(buff, &value_back, &endp);
		test_assert_idx(ret == 0, i);
		test_assert_idx(value_back == value, i);
		test_assert_idx(endp == &buff[len], i);
		i++;
	}
	test_end();

	/* not knowing exactly how large a uintmax_t is, we have to construct
	   the troublesome near-10/9*MAX strings manually by appending digits
	   to a MAX/9 string which we can easily create. Do a wider range
	   of 30 rather than the obvious 10, just in case - all are too large.*/
	test_begin("str_to_uintmax overflow corner case");
	value = UINTMAX_MAX/9-1;
	len = crappy_uintmax_to_str(buff, value);
	buff[len] = '0';
	buff[len+1] = '\0';
	for(i = 0; i <= 30; ++i) {
		int j = len + 1;
		while (buff[--j] == '9')
			buff[j] = '0';
		buff[j]++;
		value = valbase + i;
		ret = str_to_uintmax(buff, &value);
		test_assert_idx(ret < 0 && value == valbase + i, i);
	}
	test_end();
}

/* always pads with leading zeros to a size of 9 digits */
static int crappy_uintmax_to_str_hex(char *into, uintmax_t val)
{
#define BIGBASE 0x1000000000ull
#define STRINGIFY(s) #s
#define STRINGIFY2(s) STRINGIFY(s)
	int len = 0;
	if(val >= BIGBASE) {
		len = crappy_uintmax_to_str_hex(into, val/BIGBASE);
	}
	i_snprintf(into + len, 10, "%09llx",
		(unsigned long long)(val % BIGBASE));
	return len + strlen(STRINGIFY2(BIGBASE))-6;
#undef STRINGIFY2
#undef STRINGIFY
#undef BIGBASE
}
static void test_str_to_uintmax_hex(void)
{
	unsigned int i=0;
	int randrange = rand()%15+1; /* when 1, will max out on 1s */
	uintmax_t value = 0, valbase = rand() * 1000ull;
	int len, ret;
	char buff[52]; /* totally assumes < 200 bits */

	test_begin("str_to_uintmax_hex in range");
	while (i < sizeof(uintmax_t)*CHAR_BIT) {
		uintmax_t value_back;
		const char *endp;

		value = (value << 1) + 1;
		if (value >= 64)
			value -= rand()%randrange; /* don't always test the same numbers */
		len = crappy_uintmax_to_str_hex(buff, value);
		ret = str_to_uintmax_hex(buff, &value_back);
		test_assert_idx(ret == 0, i);
		test_assert_idx(value == value_back, i);

		/* test with trailing noise */
		buff[len] = 'x'; /* don't even null-terminate, let's be evil */
		value_back = 0x1234567890123456;
		ret = str_to_uintmax_hex(buff, &value_back);
		test_assert_idx(ret < 0, i);
		test_assert_idx(value_back == 0x1234567890123456, i);
		ret = str_parse_uintmax_hex(buff, &value_back, &endp);
		test_assert_idx(ret == 0, i);
		test_assert_idx(value_back == value, i);
		test_assert_idx(endp == &buff[len], i);
		i++;
	}
	test_end();

	/* not knowing exactly how large a uintmax_t is, we have to construct
	   the troublesome near-0x10/0x0F*MAX strings manually by appending digits
	   to a MAX/0x0f string which we can easily create. Do a wider range
	   of 0x30 rather than the obvious 0x10, just in case - all are too large.*/
	test_begin("str_to_uintmax_hex overflow corner case");
	value = (UINTMAX_MAX/0x0f)-1;
	len = crappy_uintmax_to_str_hex(buff, value);
	buff[len] = '0';
	buff[len+1] = '\0';
	for(i = 0; i <= 0x30; ++i) {
		int j = len + 1;
		while (buff[--j] == 'f')
			buff[j] = '0';
		if (buff[j] == '9')
			buff[j] = 'a';
		else
			buff[j]++;
		value = valbase + i;
		ret = str_to_uintmax_hex(buff, &value);
		test_assert_idx(ret < 0 && value == valbase + i, i);
	}
	test_end();
}

/* always pads with leading zeros to a size of 9 digits */
static int crappy_uintmax_to_str_oct(char *into, uintmax_t val)
{
#define BIGBASE 01000000000ull
#define STRINGIFY(s) #s
#define STRINGIFY2(s) STRINGIFY(s)
	int len = 0;
	if(val >= BIGBASE) {
		len = crappy_uintmax_to_str_oct(into, val/BIGBASE);
	}
	i_snprintf(into + len, 10, "%09llo",
		(unsigned long long)(val % BIGBASE));
	return len + strlen(STRINGIFY2(BIGBASE))-5;
#undef STRINGIFY2
#undef STRINGIFY
#undef BIGBASE
}
static void test_str_to_uintmax_oct(void)
{
	unsigned int i=0;
	int randrange = rand()%15+1; /* when 1, will max out on 1s */
	uintmax_t value = 0, valbase = rand() * 1000ull;
	int len, ret;
	char buff[69]; /* totally assumes < 200 bits */

	test_begin("str_to_uintmax_oct in range");
	while (i < sizeof(uintmax_t)*CHAR_BIT) {
		uintmax_t value_back;
		const char *endp;

		value = (value << 1) + 1;
		if (value >= 64)
			value -= rand()%randrange; /* don't always test the same numbers */
		len = crappy_uintmax_to_str_oct(buff, value);
		ret = str_to_uintmax_oct(buff, &value_back);
		test_assert_idx(ret == 0, i);
		test_assert_idx(value == value_back, i);

		/* test with trailing noise */
		buff[len] = 'x'; /* don't even null-terminate, let's be evil */
		value_back = 0x1234567890123456;
		ret = str_to_uintmax_oct(buff, &value_back);
		test_assert_idx(ret < 0, i);
		test_assert_idx(value_back == 0x1234567890123456, i);
		ret = str_parse_uintmax_oct(buff, &value_back, &endp);
		test_assert_idx(ret == 0, i);
		test_assert_idx(value_back == value, i);
		test_assert_idx(endp == &buff[len], i);
		i++;
	}
	test_end();

	/* not knowing exactly how large a uintmax_t is, we have to construct
	   the troublesome near-010/007*MAX strings manually by appending digits
	   to a MAX/007 string which we can easily create. Do a wider range
	   of 030 rather than the obvious 010, just in case - all are too large.*/
	test_begin("str_to_uintmax_oct overflow corner case");
	value = (UINTMAX_MAX/007)-1;
	len = crappy_uintmax_to_str_oct(buff, value);
	buff[len] = '0';
	buff[len+1] = '\0';
	for(i = 0; i <= 030; ++i) {
		int j = len + 1;
		while (buff[--j] == '7')
			buff[j] = '0';
		buff[j]++;
		value = valbase + i;
		ret = str_to_uintmax_oct(buff, &value);
		test_assert_idx(ret < 0 && value == valbase + i, i);
	}
	test_end();
}

static void test_str_to_u64(void)
{
	unsigned int i;
	const struct {
		const char *input;
		int ret;
		uint64_t val;
	} u64tests[] = {
		INVALID(-1),
		INVALID(foo),
		VALID(0),
		VALID(000000000000000000000000000000000000000000000000000000000000000),
		{ "000000000000000000000000000000000000000000000000000001000000001", 0, 1000000001 },
		{ "18446744073709551615", 0, 18446744073709551615ULL },
		INVALID(18446744073709551616),
		INVALID(20496382304121724010), /* 2^64*10/9 doesn't wrap */
		INVALID(20496382304121724017), /* 2^64*10/9 wraps only after addition */
		INVALID(20496382304121724020), /* 2^64*10/9 wraps on multiply*/
	};
	test_begin("str_to_uint64");
	for (i = 0; i < N_ELEMENTS(u64tests); ++i) {
		uint64_t val = 0xBADBEEF15BADF00D;
		int ret = str_to_uint64(u64tests[i].input, &val);
		test_assert_idx(ret == u64tests[i].ret, i);
		if (ret == 0)
			test_assert_idx(val == u64tests[i].val, i);
		else
			test_assert_idx(val == 0xBADBEEF15BADF00D, i);

		if (ret == 0)
			T_BEGIN {
				const char *longer = t_strconcat(u64tests[i].input, "x", NULL);
				ret = str_to_uint64(longer, &val);
				test_assert_idx(ret < 0, i);
			} T_END;
	}
	test_end();
}

static void test_str_to_u32(void)
{
	unsigned int i;
	const struct {
		const char *input;
		int ret;
		uint32_t val;
	} u32tests[] = {
		VALID(0),
		INVALID(-0),
		VALID(4294967295),
		INVALID(4294967296),
		INVALID(4772185880),
		INVALID(4772185884),
		INVALID(4772185890),
	};
	test_begin("str_to_uint32");
	for (i = 0; i < N_ELEMENTS(u32tests); ++i) {
		uint32_t val = 0xDEADF00D;
		int ret = str_to_uint32(u32tests[i].input, &val);
		test_assert_idx(ret == u32tests[i].ret, i);
		if (ret == 0)
			test_assert_idx(val == u32tests[i].val, i);
		else
			test_assert_idx(val == 0xDEADF00D, i);
	}
	test_end();
}

/* Assumes long long is 64 bit, 2's complement */
static void test_str_to_llong(void)
{
	unsigned int i;
	const struct {
		const char *input;
		int ret;
		long long val;
	} i64tests[] = {
		VALID(0),
		VALID(-0),
		INVALID(--0),
		VALID(2147483648),
		VALID(-2147483649),
		VALID(9223372036854775807),
		{ "-9223372036854775808", 0, -9223372036854775807-1 },
		INVALID(9223372036854775808),
		INVALID(-9223372036854775809),
	};
	test_begin("str_to_llong");
	for (i = 0; i < N_ELEMENTS(i64tests); ++i) {
		long long val = 123456789;
		int ret = str_to_llong(i64tests[i].input, &val);
		test_assert_idx(ret == i64tests[i].ret, i);
		if (ret == 0)
			test_assert_idx(val == i64tests[i].val, i);
		else
			test_assert_idx(val == 123456789, i);
	}
	test_end();
}

/* Assumes int is 32 bit, 2's complement */
static void test_str_to_i32(void)
{
	unsigned int i;
	const struct {
		const char *input;
		int ret;
		int val;
	} i32tests[] = {
		VALID(0),
		VALID(-0),
		INVALID(--0),
		VALID(2147483647),
		VALID(-2147483648),
		INVALID(2147483648),
		INVALID(-2147483649),
	};
	test_begin("str_to_int");
	for (i = 0; i < N_ELEMENTS(i32tests); ++i) {
		int val = 123456789;
		int ret = str_to_int(i32tests[i].input, &val);
		test_assert_idx(ret == i32tests[i].ret, i);
		if (ret == 0)
			test_assert_idx(val == i32tests[i].val, i);
		else
			test_assert_idx(val == 123456789, i);
	}
	test_end();
}

static void test_str_is_float(void)
{
	test_begin("str_is_float accepts integer");
	/* accepts integer */
	test_assert(str_is_float("0",'\0'));
	test_assert(str_is_float("1234",'\0'));
	test_end();
	test_begin("str_is_float accepts float");
	test_assert(str_is_float("0.0",'\0'));
	test_assert(str_is_float("1234.0",'\0'));
	test_assert(str_is_float("0.1234",'\0'));
	test_assert(str_is_float("1234.1234",'\0'));
	test_assert(str_is_float("0.1234 ",' '));
	test_assert(str_is_float("1234.1234",'.'));
	test_end();
	test_begin("str_is_float refuses invalid values");
	test_assert(!str_is_float(".",'\0'));
	test_assert(!str_is_float(".1234",'\0'));
	test_assert(!str_is_float("1234.",'\0'));
	test_assert(!str_is_float("i am not a float at all",'\0'));
	test_assert(!str_is_float("0x1234.0x1234",'\0'));
	test_assert(!str_is_float(".0",'\0'));
	test_assert(!str_is_float("0.",'\0'));
	test_end();
}

void test_strnum(void)
{
	/* If the above isn't true, then we do expect some failures possibly */
	test_str_to_uintmax();
	test_str_to_uintmax_hex();
	test_str_to_uintmax_oct();
	test_str_to_u64();
	test_str_to_u32();
	test_str_to_llong();
	test_str_to_i32();
	test_str_is_float();
}
