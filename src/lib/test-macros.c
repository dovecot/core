/* Copyright (c) 2021 Dovecot authors, see the included COPYING file */

#include "test-lib.h"

struct parent {
	unsigned int a;
};
struct child {
	unsigned int b;
	struct parent p;
};

static void test_container_of(void)
{
	struct child child;
	struct parent *parent = &child.p;

	test_begin("container_of()");
	struct child *ptr_child = container_of(parent, struct child, p);
	test_assert(ptr_child == &child);
	test_end();
}

static void test_pointer_cast(void)
{
#define TEST_POINTER_CAST(type, prefix, value) \
	type prefix ## _num = value; \
	void *prefix ## _ptr = POINTER_CAST(prefix ## _num); \
	test_assert(POINTER_CAST_TO(prefix ## _ptr, type) == prefix ## _num);
	test_begin("POINTER_CAST");

	TEST_POINTER_CAST(unsigned int, uint, 0x87654321);
	TEST_POINTER_CAST(uint32_t, uint32, 0xf00dabcd);
	TEST_POINTER_CAST(uint16_t, uint16, 0x9876);
	TEST_POINTER_CAST(uint8_t, uint8, 0xf8);
#if SIZEOF_VOID_P == 8
	TEST_POINTER_CAST(unsigned long, ulong, 0xfedcba9876543210);
	TEST_POINTER_CAST(size_t, size, 0xfedcba9876543210);
#else
	TEST_POINTER_CAST(unsigned long, ulong, 0xfedcba98);
	TEST_POINTER_CAST(size_t, size, 0xfedcba98);
#endif

	test_end();
}

static void test_ptr_offset(void)
{
	uint32_t foo[] = { 1, 2, 3 };
	const uint32_t foo2[] = { 1, 2, 3 };

	test_begin("PTR_OFFSET");
	test_assert(PTR_OFFSET(foo, 4) == &foo[1]);
	test_assert(CONST_PTR_OFFSET(foo2, 8) == &foo2[2]);
	test_end();
}

void test_macros(void)
{
	test_container_of();
	test_pointer_cast();
	test_ptr_offset();
}
