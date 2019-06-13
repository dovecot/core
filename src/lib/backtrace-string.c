/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "backtrace-string.h"

#define MAX_STACK_SIZE 30
#define STACK_SKIP_COUNT 2

#if defined(HAVE_LIBUNWIND)

#include <libunwind.h>

int backtrace_append(string_t *str)
{
	char proc_name[256];
	int ret;
	unsigned int fp = 0;
	unw_cursor_t c;
	unw_context_t ctx;
	unw_proc_info_t pip;
	bool success = FALSE;

	if ((ret = unw_getcontext(&ctx)) != 0) {
		str_printfa(str, "unw_getcontext() failed: %d", ret);
		return -1;
	}
	if ((ret = unw_init_local(&c, &ctx)) != 0) {
		str_printfa(str, "unw_init_local() failed: %d", ret);
		return -1;
	}

	do {
		if (fp < STACK_SKIP_COUNT) {
			fp++;
			continue;
		}
		str_printfa(str, "#%d ", fp - STACK_SKIP_COUNT);
		if ((ret = unw_get_proc_info(&c, &pip)) != 0) {
			str_printfa(str, "[unw_get_proc_info_failed(): %d]", ret);
		} else if (pip.start_ip == 0 || pip.end_ip == 0) {
			str_append(str, "[no start/end information]");
		} else if ((ret = unw_get_proc_name(&c, proc_name, sizeof(proc_name), 0)) != 0 &&
			   ret != UNW_ENOMEM) {
			str_printfa(str, "[unw_get_proc_name() failed: %d]", ret);
		} else {
			str_append_max(str, proc_name, sizeof(proc_name));
			str_printfa(str, "[0x%08lx]", pip.start_ip);
			success = TRUE;
		}
		str_append(str, " -> ");
		fp++;
	} while ((ret = unw_step(&c)) > 0);

	/* remove ' -> ' */
	if (str->used > 4)
		str_truncate(str, str->used - 4);
	return ret == 0 && success ? 0 : -1;
}

#elif defined(HAVE_BACKTRACE_SYMBOLS) && defined(HAVE_EXECINFO_H)
/* Linux */
#include <execinfo.h>

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
