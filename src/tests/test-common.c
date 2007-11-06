/* Copyright (c) 2007 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "test-common.h"

#include <stdio.h>

#define OUT_NAME_ALIGN 30

static unsigned int failure_count;
static unsigned int total_count;

void test_out(const char *name, bool success)
{
	int i;

	fputs(name, stdout);
	putchar(' ');
	for (i = strlen(name) + 1; i < OUT_NAME_ALIGN; i++)
		putchar('.');
	fputs(" : ", stdout);
	if (success)
		puts("ok");
	else {
		puts("FAILED");
		failure_count++;
	}
	total_count++;
}

void test_init(void)
{
	failure_count = 0;
	total_count = 0;

	lib_init();
}

int test_deinit(void)
{
	printf("%u / %u tests failed\n", failure_count, total_count);
	return failure_count == 0 ? 0 : 1;
}
