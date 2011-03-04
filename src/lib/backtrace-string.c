/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "backtrace-string.h"

#define MAX_STACK_SIZE 30
#define STACK_SKIP_COUNT 2

#if defined(HAVE_BACKTRACE_SYMBOLS) && defined(HAVE_EXECINFO_H)
/* Linux */
#include <execinfo.h>
#include <stdlib.h>

int backtrace_append(string_t *str)
{
	void *stack[MAX_STACK_SIZE];
	char **strings;
	int ret, i;

	ret = backtrace(stack, N_ELEMENTS(stack));
	if (ret <= STACK_SKIP_COUNT)
		return -1;

	strings = backtrace_symbols(stack, ret);
	for (i = STACK_SKIP_COUNT; i < ret; i++) {
		if (i > STACK_SKIP_COUNT)
			str_append(str, " -> ");

		if (strings != NULL)
			str_append(str, strings[i]);
		else {
			/* out of memory case */
			str_printfa(str, "0x%p", stack[i]);
		}
	}
	free(strings);
	return 0;
}
#elif defined(HAVE_WALKCONTEXT) && defined(HAVE_UCONTEXT_H)
/* Solaris */
#include <ucontext.h>

struct walk_context {
	string_t *str;
	unsigned int pos;
};

static int walk_callback(uintptr_t ptr, int signo ATTR_UNUSED,
			 void *context)
{
	struct walk_context *ctx = context;

	if (ctx->pos >= STACK_SKIP_COUNT) {
		if (ctx->pos > STACK_SKIP_COUNT)
			str_append(ctx->str, " -> ");
		str_printfa(ctx->str, "0x%p", (void *)ptr);
	}
	ctx->pos++;
	return 0;
}

int backtrace_append(string_t *str)
{
	ucontext_t uc;
	struct walk_context ctx;

	if (getcontext(&uc) < 0)
		return -1;

	ctx.str = str;
	ctx.pos = 0;
	walkcontext(&uc, walk_callback, &ctx);
	return 0;
}
#else
int backtrace_append(string_t *str ATTR_UNUSED)
{
	return -1;
}
#endif

int backtrace_get(const char **backtrace_r)
{
	string_t *str;

	str = t_str_new(512);
	if (backtrace_append(str) < 0)
		return -1;

	*backtrace_r = str_c(str);
	return 0;
}
