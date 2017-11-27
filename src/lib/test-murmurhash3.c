#include "test-lib.h"
#include "murmurhash3.h"

struct murmur3_test_vectors {
	const char *input;
	size_t len;
	uint32_t seed;
	uint32_t result[4]; /* fits all results */
};

static void test_murmurhash3_algorithm(const char *name,
				       void (*func)(const void*,size_t,uint32_t,unsigned char[]),
				       size_t result_size,
				       const struct murmur3_test_vectors *vectors,
				       unsigned int tests)
{
	test_begin(t_strdup_printf("murmurhash3 (%s)", name));

	for(unsigned int i = 0; i < tests; i++) {
		unsigned char result[result_size];
		func(vectors[i].input, vectors[i].len, vectors[i].seed, result);
		test_assert_idx(memcmp(result, vectors[i].result, sizeof(result)) == 0, i);
	}

	test_end();
}

static void test_murmurhash3_32(void)
{
	struct murmur3_test_vectors vectors[] = {
		{ "", 0, 0, { 0, 0, 0, 0}},
		{ "", 0, 0x1, { 0x514E28B7, 0, 0, 0 }},
		{ "", 0, 0xFFFFFFFF, { 0x81F16F39, 0, 0, 0 }},
		{ "\0\0\0\0", 4, 0, { 0x2362F9DE, 0, 0, 0 }},
		{ "aaaa", 4, 0x9747b28c, { 0x5A97808A, 0, 0, 0 }},
		{ "aaa", 3, 0x9747b28c, { 0x283E0130, 0, 0, 0 }},
		{ "aa", 2, 0x9747b28c, { 0x5D211726, 0, 0, 0 }},
		{ "a", 1, 0x9747b28c, { 0x7FA09EA6, 0, 0, 0 }},
		{ "abcd", 4, 0x9747b28c, { 0xF0478627, 0, 0, 0 }},
		{ "abc", 3, 0x9747b28c, { 0xC84A62DD, 0, 0, 0 }},
		{ "ab", 2, 0x9747b28c, { 0x74875592, 0, 0, 0 }},
		{ "Hello, world!", 13, 0x9747b28c, { 0x24884CBA, 0, 0, 0 }},
		{
		  "\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80",
		  16,
		  0x9747b28c,
		  { 0xD58063C1, 0, 0, 0 }
		}, /* 8 U+03C0 (Greek Small Letter Pi) */
		{
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaa",
		  256,
		  0x9747b28c,
		  { 0x37405BDC, 0, 0, 0 }
		},
	};

	test_murmurhash3_algorithm("murmurhash3_32", murmurhash3_32,
				   MURMURHASH3_32_RESULTBYTES,
				   vectors, N_ELEMENTS(vectors));
}

static void test_murmurhash3_128(void)
{
	struct murmur3_test_vectors vectors[] = {
#ifdef _LP64
		{ "", 0, 0x00000000, { 0x00000000, 0x00000000, 0x00000000, 0x00000000 }},
		{ "", 0, 0x00000001, { 0x6eff5cb5, 0x4610abe5, 0x78f83583, 0x51622daa }},
		{ "", 0, 0xffffffff, { 0x9d3bc9ec, 0x6af1df4d, 0x1ee6446b, 0x85742112 }},
		{ "\0\0\0\0", 4, 0x00000000, { 0xd84c76bc, 0xcfa0f7dd, 0x1cf526f1, 0x58962316 }},
		{ "aaaa", 4, 0x9747b28c, { 0x5e649bf0, 0xb4e0a5f7, 0x038c569f, 0xa5d3e8e9 }},
		{ "aaa", 3, 0x9747b28c, { 0xe4c7466b, 0x8ea5e37a, 0x35dc931c, 0xf925bef0 }},
		{ "aa", 2, 0x9747b28c, { 0xbee5bb1f, 0x12a698a9, 0x5e269401, 0xe93630ff }},
		{ "a", 1, 0x9747b28c, { 0x2db25a1d, 0x5ce8d851, 0x9208f004, 0x9e6dab0f }},
		{ "abcd", 4, 0x9747b28c, { 0xac553791, 0x49b4709e, 0xe9d3a7bb, 0x8a7e67e7 }},
		{ "abc", 3, 0x9747b28c, { 0xbfc3cedc, 0x3743630d, 0x20b504bf, 0xcde0a234 }},
		{ "ab", 2, 0x9747b28c, { 0x1a44280b, 0x8434eead, 0x63ce372b, 0x7eb933e7 }},
		{ "Hello, world!", 13, 0x9747b28c, { 0x62a8392e, 0xedc485d6, 0x31d576ba, 0xf85e7e76 }},
		{
		  "\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80",
		  16,
		  0x9747b28c,
		  { 0xc0361a1f, 0x96ea5bd8, 0x094be17b, 0xf8b72bd0 }
		},
		{
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaa",
		  256,
		  0x9747b28c,
		  { 0xa5dec1c4, 0x07bd957c, 0x1f6cee55, 0xc4d8bb8d }
		},
#else	/* 32 bit test vectors */
		{ "", 0, 0x00000000, { 0x00000000, 0x00000000, 0x00000000, 0x00000000 }},
		{ "", 0, 0x00000001, { 0x88c4adec, 0x54d201b9, 0x54d201b9, 0x54d201b9 }},
		{ "", 0, 0xffffffff, { 0x051e08a9, 0x989d49f7, 0x989d49f7, 0x989d49f7 }},
		{ "\0\0\0\0", 4, 0x00000000, { 0xcc066f1f, 0x9e517840, 0x9e517840, 0x9e517840 }},
		{ "aaaa", 4, 0x9747b28c, { 0x36804cef, 0x2a61c224, 0x2a61c224, 0x2a61c224 }},
		{ "aaa", 3, 0x9747b28c, { 0x838389be, 0x9aad7f88, 0x9aad7f88, 0x9aad7f88 }},
		{ "aa", 2, 0x9747b28c, { 0xdfbe4a86, 0x4a9c350b, 0x4a9c350b, 0x4a9c350b }},
		{ "a", 1, 0x9747b28c, { 0x084ef944, 0x21a1186e, 0x21a1186e, 0x21a1186e }},
		{ "abcd", 4, 0x9747b28c, { 0x4795c529, 0xcec1885e, 0xcec1885e, 0xcec1885e }},
		{ "abc", 3, 0x9747b28c, { 0xd6359eaf, 0x48fc3ac3, 0x48fc3ac3, 0x48fc3ac3 }},
		{ "ab", 2, 0x9747b28c, { 0x3837d795, 0xc7fe5896, 0xc7fe5896, 0xc7fe5896 }},
		{ "Hello, world!", 13, 0x9747b28c, { 0x756d5460, 0xbb872216, 0xb7d48b7c, 0x53c8c636 }},
		{
		  "\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80\xcf\x80",
		  16,
		  0x9747b28c,
		  { 0xaf2ad325, 0x3a74df88, 0x38cc7534, 0xf197cc0d }
		},
		{
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		  "aaaaaaaaaaaaaaaaaaaa",
		  256,
		  0x9747b28c,
		  { 0xd3f2b7bb, 0xf666c0cc, 0xd4a40060, 0x5ec8d32a }
		},
#endif
	};

	test_murmurhash3_algorithm("murmurhash3_128", murmurhash3_128,
				   MURMURHASH3_128_RESULTBYTES,
				   vectors, N_ELEMENTS(vectors));
}

void test_murmurhash3(void)
{
	test_murmurhash3_32();
	test_murmurhash3_128();
}
