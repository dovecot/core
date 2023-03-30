/* Copyright (c) 2006-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "str.h"
#include "backtrace-string.h"

#define MAX_STACK_SIZE 30
#define BACKTRACE_SKIP_PREFIX "backtrace_"

#if defined(HAVE_LIBUNWIND)

#include <libunwind.h>

static int backtrace_append_unwind(string_t *str, const char **error_r)
{
	size_t str_orig_size = str_len(str);
	char proc_name[256];
	int ret;
	unsigned int fp = 0;
	unw_cursor_t c;
	unw_context_t ctx;
	unw_proc_info_t pip;
	bool success = FALSE;

	if ((ret = unw_getcontext(&ctx)) != 0) {
		*error_r = t_strdup_printf("unw_getcontext() failed: %d", ret);
		return -1;
	}
	if ((ret = unw_init_local(&c, &ctx)) != 0) {
		*error_r = t_strdup_printf("unw_init_local() failed: %d", ret);
		return -1;
	}

	do {
		str_printfa(str, "#%d ", fp);
		if ((ret = unw_get_proc_info(&c, &pip)) != 0) {
			str_printfa(str, "[unw_get_proc_info_failed(): %d]", ret);
		} else if (pip.start_ip == 0 || pip.end_ip == 0) {
			str_append(str, "[no start/end information]");
		} else if ((ret = unw_get_proc_name(&c, proc_name, sizeof(proc_name), 0)) != 0 &&
			   ret != UNW_ENOMEM) {
			str_printfa(str, "[unw_get_proc_name() failed: %d]", ret);
		} else if (!success && str_begins_with(proc_name, BACKTRACE_SKIP_PREFIX)) {
			str_truncate(str, str_orig_size);
			continue;
		} else {
			str_append_max(str, proc_name, sizeof(proc_name));
			str_printfa(str, "[0x%08zx]", pip.start_ip);
			success = TRUE;
		}
		str_append(str, " -> ");
		fp++;
	} while ((ret = unw_step(&c)) > 0);

	/* remove ' -> ' */
	if (str->used > 4)
		str_truncate(str, str->used - 4);
	if (ret < 0) {
		*error_r = t_strdup_printf("unw_step() failed: %d", ret);
		return -1;
	}
	if (!success) {
		*error_r = t_strdup_printf("No symbols found (process chrooted?)");
		return -1;
	}
	return 0;
}
#endif

#if defined(HAVE_BACKTRACE_SYMBOLS) && defined(HAVE_EXECINFO_H)
/* Linux */
#include <execinfo.h>

static int backtrace_append_libc(string_t *str, const char **error_r)
{
	size_t str_orig_size = str_len(str);
	void *stack[MAX_STACK_SIZE];
	char **strings;
	int ret, i;

	ret = backtrace(stack, N_ELEMENTS(stack));
	if (ret <= 0) {
		*error_r = "backtrace() failed";
		return -1;
	}

	strings = backtrace_symbols(stack, ret);
	if (strings == NULL) {
		*error_r = "backtrace_symbols() failed";
		return -1;
	}
	for (i = 0; i < ret; i++) {
		if (str_len(str) > str_orig_size)
			str_append(str, " -> ");

		if (str_len(str) != str_orig_size ||
		    !str_begins_with(strings[i], BACKTRACE_SKIP_PREFIX)) {
			/* String often contains a full path to the binary,
			   followed by the function name. The path causes the
			   backtrace to be excessively large and we don't
			   especially care about it, so just skip over it. */
			const char *suffix = strrchr(strings[i], '/');
			if (suffix != NULL)
				suffix++;
			else
				suffix = strings[i];
			str_append(str, suffix);
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

	if (ctx->pos > 0)
		str_append(ctx->str, " -> ");
	str_printfa(ctx->str, "0x%p", (void *)ptr);
	ctx->pos++;
	return 0;
}

static int backtrace_append_libc(string_t *str, const char **error_r)
{
	ucontext_t uc;
	struct walk_context ctx;

	if (getcontext(&uc) < 0) {
		*error_r = t_strdup_printf("getcontext() failed: %m");
		return -1;
	}

	ctx.str = str;
	ctx.pos = 0;
	walkcontext(&uc, walk_callback, &ctx);
	return 0;
}
#else
static int
backtrace_append_libc(string_t *str ATTR_UNUSED, const char **error_r)
{
	*error_r = "Missing implementation";
	return -1;
}
#endif

int backtrace_append(string_t *str, const char **error_r)
{
#if defined(HAVE_LIBUNWIND)
	size_t orig_len = str_len(str);
	if (backtrace_append_unwind(str, error_r) == 0)
		return 0;
	/* failed to get useful backtrace. libc's own method is likely
	   better. */
	str_truncate(str, orig_len);
#endif
	return backtrace_append_libc(str, error_r);
}

int backtrace_get(const char **backtrace_r, const char **error_r)
{
	string_t *str;

	str = t_str_new(512);
	if (backtrace_append(str, error_r) < 0)
		return -1;

	*backtrace_r = str_c(str);
	return 0;
}
