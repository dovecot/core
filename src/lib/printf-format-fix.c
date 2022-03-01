/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "printf-format-fix.h"

static const char *
fix_format_real(const char *fmt, const char *p, size_t *len_r)
{
	const char *errstr;
	char *buf;
	size_t len1, len2, len3;

	i_assert((size_t)(p - fmt) < INT_MAX);
	i_assert(p[0] == '%' && p[1] == 'm');

	errstr = strerror(errno);

	/* we'll assume that there's only one %m in the format string.
	   this simplifies the code and there's really no good reason to have
	   it multiple times. Callers can trap this case themselves. */
	len1 = p - fmt;
	len2 = strlen(errstr);
	len3 = strlen(p + 2);

	/* @UNSAFE */
	buf = t_buffer_get(len1 + len2 + len3 + 1);
	memcpy(buf, fmt, len1);
	memcpy(buf + len1, errstr, len2);
	memcpy(buf + len1 + len2, p + 2, len3 + 1);

	*len_r = len1 + len2 + len3;
	return buf;
}

static bool verify_length(const char **p)
{
	if (**p == '*') {
		/* We don't bother supporting "*m$" - it's not used
		   anywhere and seems a bit dangerous. */
		*p += 1;
	} else if (**p >= '0' && **p <= '9') {
		/* Limit to 4 digits - we'll never want more than that.
		   Some implementations might not handle long digits
		   correctly, or maybe even could be used for DoS due
		   to using too much CPU. If you want to express '99'
		   as '00099', then you lose in this function. */
		unsigned int i = 0;
		do {
			*p += 1;
			if (++i > 4)
				return FALSE;
		} while (**p >= '0' && **p <= '9');
	}
	return TRUE;
}

static const char *
printf_format_fix_noalloc(const char *format, size_t *len_r)
{
	/* NOTE: This function is overly strict in what it accepts. Some
	   format strings that are valid (and safe) in C99 will cause a panic
	   here. This is because we don't really need to support the weirdest
	   special cases, and we're also being extra careful not to pass
	   anything to the underlying libc printf, which might treat the string
	   differently than us and unexpectedly handling it as %n. For example
	   "%**%n" with glibc. */

	/* Allow only the standard C99 flags. There are also <'> and <I> flags,
	   but we don't really need them. And at worst if they're not supported
	   by the underlying printf, they could potentially be used to work
	   around our restrictions. */
	const char printf_flags[] = "#0- +";
	/* As a tiny optimization keep the most commonly used conversion
	   specifiers first, so strchr() stops early. */
	static const char *printf_specifiers = "sudcixXpoeEfFgGaA";
	const char *ret, *p, *p2;
	char *flag;

	p = ret = format;
	while ((p2 = strchr(p, '%')) != NULL) {
		const unsigned int start_pos = p2 - format;

		p = p2+1;
		if (*p == '%') {
			/* we'll be strict and allow %% only when there are no
			   optional flags or modifiers. */
			p++;
			continue;
		}
		/* 1) zero or more flags. We'll add a further restriction that
		   each flag can be used only once, since there's no need to
		   use them more than once, and some implementations might
		   add their own limits. */
		bool printf_flags_seen[N_ELEMENTS(printf_flags)] = { FALSE, };
		while (*p != '\0' &&
		       (flag = strchr(printf_flags, *p)) != NULL) {
			unsigned int flag_idx = flag - printf_flags;

			if (printf_flags_seen[flag_idx]) {
				i_panic("Duplicate %% flag '%c' starting at #%u in '%s'",
					*p, start_pos, format);
			}
			printf_flags_seen[flag_idx] = TRUE;
			p++;
		}

		/* 2) Optional minimum field width */
		if (!verify_length(&p)) {
			i_panic("Too large minimum field width starting at #%u in '%s'",
				start_pos, format);
		}

		/* 3) Optional precision */
		if (*p == '.') {
			p++;
			if (!verify_length(&p)) {
				i_panic("Too large precision starting at #%u in '%s'",
					start_pos, format);
			}
		}

		/* 4) Optional length modifier */
		switch (*p) {
		case 'h':
			if (*++p == 'h')
				p++;
			break;
		case 'l':
			if (*++p == 'l')
				p++;
			break;
		case 'L':
		case 'j':
		case 'z':
		case 't':
			p++;
			break;
		}

		/* 5) conversion specifier */
		if (*p == '\0' || strchr(printf_specifiers, *p) == NULL) {
			switch (*p) {
			case 'n':
				i_panic("%%n modifier used");
			case 'm':
				if (ret != format)
					i_panic("%%m used twice");
				ret = fix_format_real(format, p-1, len_r);
				break;
			case '\0':
				i_panic("Missing %% specifier starting at #%u in '%s'",
					start_pos, format);
			default:
				i_panic("Unsupported 0x%02x specifier starting at #%u in '%s'",
					*p, start_pos, format);
			}
		}
		p++;
	}

	if (ret == format)
		*len_r = p - format + strlen(p);
	return ret;
}

const char *printf_format_fix_get_len(const char *format, size_t *len_r)
{
	const char *ret;

	ret = printf_format_fix_noalloc(format, len_r);
	if (ret != format)
		t_buffer_alloc(*len_r + 1);
	return ret;
}

const char *printf_format_fix(const char *format)
{
	const char *ret;
	size_t len;

	ret = printf_format_fix_noalloc(format, &len);
	if (ret != format)
		t_buffer_alloc(len + 1);
	return ret;
}

const char *printf_format_fix_unsafe(const char *format)
{
	size_t len;

	return printf_format_fix_noalloc(format, &len);
}
