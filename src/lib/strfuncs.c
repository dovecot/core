/*
 strfuncs.c : String manipulation functions (note: LGPL, because the )

    Copyright (C) 2001-2002 Timo Sirainen

    printf_string_upper_bound() code is taken from GLIB:
    Copyright (C) 1995-1997  Peter Mattis, Spencer Kimball and Josh MacDonald
    Modified by the GLib Team and others 1997-1999.


    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Library General Public
    License as published by the Free Software Foundation; either
    version 2 of the License, or (at your option) any later version.
  
    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
    Library General Public License for more details.
  
    You should have received a copy of the GNU Library General Public
    License along with this library; if not, write to the
    Free Software Foundation, Inc., 59 Temple Place - Suite 330,
    Boston, MA 02111-1307, USA.
*/

#include "lib.h"
#include "strfuncs.h"

#include <stdio.h>
#include <limits.h>
#include <ctype.h>

#define STRCONCAT_BUFSIZE 512

typedef void *(*ALLOC_FUNC)(Pool, size_t);

static void *tp_malloc(Pool pool __attr_unused__, size_t size)
{
        return t_malloc(size);
}

typedef union  _GDoubleIEEE754  GDoubleIEEE754;
#define G_IEEE754_DOUBLE_BIAS   (1023)
/* multiply with base2 exponent to get base10 exponent (nomal numbers) */
#define G_LOG_2_BASE_10         (0.30102999566398119521)
#if G_BYTE_ORDER == G_LITTLE_ENDIAN
union _GDoubleIEEE754
{
  double v_double;
  struct {
    unsigned int mantissa_low : 32;
    unsigned int mantissa_high : 20;
    unsigned int biased_exponent : 11;
    unsigned int sign : 1;
  } mpn;
};
#elif G_BYTE_ORDER == G_BIG_ENDIAN
union _GDoubleIEEE754
{
  double v_double;
  struct {
    unsigned int sign : 1;
    unsigned int biased_exponent : 11;
    unsigned int mantissa_high : 20;
    unsigned int mantissa_low : 32;
  } mpn;
};
#else /* !G_LITTLE_ENDIAN && !G_BIG_ENDIAN */
#error unknown ENDIAN type
#endif /* !G_LITTLE_ENDIAN && !G_BIG_ENDIAN */

typedef struct
{
  unsigned int min_width;
  unsigned int precision;
  int alternate_format, zero_padding, adjust_left, locale_grouping;
  int add_space, add_sign, possible_sign, seen_precision;
  int mod_half, mod_long, mod_extra_long;
} PrintfArgSpec;

#if (SIZEOF_LONG > 4) || (SIZEOF_VOID_P > 4)
#  define HONOUR_LONGS 1
#else
#  define HONOUR_LONGS 0
#endif

size_t printf_string_upper_bound(const char *format, va_list args)
{
  size_t len = 1;

  if (!format)
    return len;

  while (*format)
    {
      register char c = *format++;

      if (c != '%')
        len += 1;
      else /* (c == '%') */
        {
          PrintfArgSpec spec;
          int seen_l = FALSE, conv_done = FALSE;
          unsigned int conv_len = 0;
          const char *spec_start = format;

          memset(&spec, 0, sizeof(spec));
          do
            {
              c = *format++;
              switch (c)
                {
                  GDoubleIEEE754 u_double;
                  unsigned int v_uint;
                  int v_int;
                  const char *v_string;

                  /* beware of positional parameters
                   */
                case '$':
                  i_warning (GNUC_PRETTY_FUNCTION
                             "(): unable to handle positional parameters (%%n$)");
                  len += 1024; /* try adding some safety padding */
                  break;

                  /* parse flags
                   */
                case '#':
                  spec.alternate_format = TRUE;
                  break;
                case '0':
                  spec.zero_padding = TRUE;
                  break;
                case '-':
                  spec.adjust_left = TRUE;
                  break;
                case ' ':
                  spec.add_space = TRUE;
                  break;
                case '+':
                  spec.add_sign = TRUE;
                  break;
                case '\'':
                  spec.locale_grouping = TRUE;
                  break;

                  /* parse output size specifications
                   */
                case '.':
                  spec.seen_precision = TRUE;
                  break;
                case '1':
                case '2':
                case '3':
                case '4':
                case '5':
                case '6':
                case '7':
                case '8':
                case '9':
                  v_uint = c - '0';
                  c = *format;
                  while (c >= '0' && c <= '9')
                    {
                      format++;
                      v_uint = v_uint * 10 + (c - '0');
                      c = *format;
                    }
                  if (spec.seen_precision)
                    spec.precision = I_MAX (spec.precision, v_uint);
                  else
                    spec.min_width = I_MAX (spec.min_width, v_uint);
                  break;
                case '*':
                  v_int = va_arg (args, int);
                  if (spec.seen_precision)
                    {
                      /* forget about negative precision */
                      if (v_int >= 0)
                        spec.precision = I_MAX ((int)spec.precision, v_int);
                    }
                  else
                    {
                      if (v_int < 0)
                        {
                          v_int = - v_int;
                          spec.adjust_left = TRUE;
                        }
                      spec.min_width = I_MAX ((int)spec.min_width, v_int);
                    }
                  break;

                  /* parse type modifiers
                   */
                case 'h':
                  spec.mod_half = TRUE;
                  break;
                case 'l':
                  if (!seen_l)
                    {
                      spec.mod_long = TRUE;
                      seen_l = TRUE;
                      break;
                    }
                  /* else, fall through */
                case 'L':
                case 'q':
                  spec.mod_long = TRUE;
                  spec.mod_extra_long = TRUE;
                  break;
                case 'z':
                case 'Z':
#if GLIB_SIZEOF_SIZE_T > 4
                  spec.mod_long = TRUE;
                  spec.mod_extra_long = TRUE;
#endif /* GLIB_SIZEOF_SIZE_T > 4 */
                  break;
                case 't':
#if GLIB_SIZEOF_PTRDIFF_T > 4
                  spec.mod_long = TRUE;
                  spec.mod_extra_long = TRUE;
#endif /* GLIB_SIZEOF_PTRDIFF_T > 4 */
                  break;
                case 'j':
#if GLIB_SIZEOF_INTMAX_T > 4
                  spec.mod_long = TRUE;
                  spec.mod_extra_long = TRUE;
#endif /* GLIB_SIZEOF_INTMAX_T > 4 */
                  break;

                  /* parse output conversions
                   */
                case '%':
                  conv_len += 1;
                  break;
                case 'O':
                case 'D':
                case 'I':
                case 'U':
                  /* some C libraries feature long variants for these as well? */
                  spec.mod_long = TRUE;
                  /* fall through */
                case 'o':
                  conv_len += 2;
                  /* fall through */
                case 'd':
                case 'i':
                  conv_len += 1; /* sign */
                  /* fall through */
                case 'u':
                  conv_len += 4;
                  /* fall through */
                case 'x':
                case 'X':
                  spec.possible_sign = TRUE;
                  conv_len += 10;
                  if (spec.mod_long && HONOUR_LONGS)
                    conv_len *= 2;
                  if (spec.mod_extra_long)
                    conv_len *= 2;
                  if (spec.mod_extra_long)
                    {
#ifdef G_HAVE_GINT64
                      (void) va_arg (args, gint64);
#else
                      (void) va_arg (args, long);
#endif
                    }
                  else if (spec.mod_long)
                    (void) va_arg (args, long);
                  else
                    (void) va_arg (args, int);
                  break;
                case 'A':
                case 'a':
                  /*          0x */
                  conv_len += 2;
                  /* fall through */
                case 'g':
                case 'G':
                case 'e':
                case 'E':
                case 'f':
                  spec.possible_sign = TRUE;
                  /*          n   .   dddddddddddddddddddddddd   E   +-  eeee */
                  conv_len += 1 + 1 + I_MAX (24, spec.precision) + 1 + 1 + 4;
                  if (spec.mod_extra_long)
                    i_warning (GNUC_PRETTY_FUNCTION
                               "(): unable to handle long double, collecting double only");
#ifdef HAVE_LONG_DOUBLE
#error need to implement special handling for long double
#endif
                  u_double.v_double = va_arg (args, double);
                  /* %f can expand up to all significant digits before '.' (308) */
                  if (c == 'f' &&
                      u_double.mpn.biased_exponent > 0 && u_double.mpn.biased_exponent < 2047)
                    {
                      int exp = u_double.mpn.biased_exponent;

                      exp -= G_IEEE754_DOUBLE_BIAS;
                      exp = exp * G_LOG_2_BASE_10 + 1;
                      conv_len += exp;
                    }
                  /* some printf() implementations require extra padding for rounding */
                  conv_len += 2;
                  /* we can't really handle locale specific grouping here */
                  if (spec.locale_grouping)
                    conv_len *= 2;
                  break;
                case 'C':
                  spec.mod_long = TRUE;
                  /* fall through */
                case 'c':
                  conv_len += spec.mod_long ? MB_LEN_MAX : 1;
                  (void) va_arg (args, int);
                  break;
                case 'S':
                  spec.mod_long = TRUE;
                  /* fall through */
                case 's':
                  v_string = va_arg (args, char*);
                  if (!v_string)
                    conv_len += 8; /* hold "(null)" */
                  else if (spec.seen_precision)
                    conv_len += spec.precision;
                  else
                    conv_len += strlen (v_string);
                  conv_done = TRUE;
                  if (spec.mod_long)
                    {
                      i_warning (GNUC_PRETTY_FUNCTION
                                 "(): unable to handle wide char strings");
                      len += 1024; /* try adding some safety padding */
                    }
                  break;
                case 'P': /* do we actually need this? */
                  /* fall through */
                case 'p':
                  spec.alternate_format = TRUE;
                  conv_len += 10;
                  if (HONOUR_LONGS)
                    conv_len *= 2;
                  /* fall through */
                case 'n':
                  conv_done = TRUE;
                  (void) va_arg (args, void*);
                  break;
                case 'm':
                  /* there's not much we can do to be clever */
                  v_string = strerror (errno);
                  v_uint = v_string ? strlen (v_string) : 0;
                  conv_len += I_MAX (256, v_uint);
                  break;

                  /* handle invalid cases
                   */
                case '\000':
                  /* no conversion specification, bad bad */
                  conv_len += format - spec_start;
                  break;
                default:
                  i_warning (GNUC_PRETTY_FUNCTION
                             "(): unable to handle `%c' while parsing format",
                             c);
                  break;
                }
              conv_done |= conv_len > 0;
            }
          while (!conv_done);
          /* handle width specifications */
          conv_len = I_MAX (conv_len, I_MAX (spec.precision, spec.min_width));
          /* handle flags */
          conv_len += spec.alternate_format ? 2 : 0;
          conv_len += (spec.add_space || spec.add_sign || spec.possible_sign);
          /* finally done */
          len += conv_len;
        } /* else (c == '%') */
    } /* while (*format) */

  return len;
}

static const char *fix_format_real(const char *fmt, const char *p)
{
	const char *errstr;
	char *buf;
	size_t pos, alloc, errlen;

	errstr = strerror(errno);
	errlen = strlen(errstr);

	pos = (size_t) (p-fmt);
	i_assert(pos < SSIZE_T_MAX);

	alloc = pos + errlen + 128;
	buf = t_buffer_get(alloc);

	memcpy(buf, fmt, pos);

	while (*p != '\0') {
		if (*p == '%' && p[1] == 'm') {
			if (pos+errlen+1 > alloc) {
				alloc += errlen+1 + 128;
				buf = t_buffer_get(alloc);
			}

			memcpy(buf+pos, errstr, errlen);
			pos += errlen;
			p += 2;
		} else {
			/* p + \0 */
			if (pos+2 > alloc) {
				alloc += 128;
				buf = t_buffer_get(alloc);
			}

			buf[pos++] = *p;
			p++;
		}
	}

	buf[pos++] = '\0';
	t_buffer_alloc(pos);
	return buf;
}

/* replace %m with strerror() */
static const char *fix_format(const char *fmt)
{
	const char *p;

	for (p = fmt; *p != '\0'; p++) {
		if (*p == '%' && p[1] == 'm')
			return fix_format_real(fmt, p);
	}

	return fmt;
}

int i_snprintf(char *str, size_t max_chars, const char *format, ...)
{
#ifdef HAVE_VSNPRINTF
	va_list args;
	int ret;

	i_assert(str != NULL);
	i_assert(max_chars < SSIZE_T_MAX);
	i_assert(format != NULL);

	t_push();
	va_start(args, format);
	ret = vsnprintf(str, max_chars, fix_format(format), args);
	va_end(args);
	t_pop();

	if (ret < 0) {
		str[max_chars-1] = '\0';
		ret = strlen(str);
	}

	return ret;
#else
	char *buf;
	va_list args;
        int len;

	i_assert(str != NULL);
	i_assert(max_chars < SSIZE_T_MAX);
	i_assert(format != NULL);

	t_push();

	va_start(args, format);
	format = fix_format(format);
	buf = t_buffer_get(printf_string_upper_bound(format, args));
	va_end(args);

	len = vsprintf(buf, format, args);
	if (len >= (int)max_chars)
		len = max_chars-1;

        memcpy(str, buf, len);
	str[len] = '\0';

	t_pop();
	return len;
#endif
}

#define STRDUP_CORE(alloc_func, str) STMT_START { \
	void *mem;				\
	size_t len;				\
						\
	for (len = 0; (str)[len] != '\0'; )	\
		len++;				\
	len++;					\
	mem = alloc_func;			\
	memcpy(mem, str, sizeof(str[0])*len);	\
	return mem;				\
	} STMT_END

char *p_strdup(Pool pool, const char *str)
{
	if (str == NULL)
                return NULL;

        STRDUP_CORE(p_malloc(pool, len), str);
}

const char *t_strdup(const char *str)
{
	if (str == NULL)
                return NULL;

        STRDUP_CORE(t_malloc(len), str);
}

char *t_strdup_noconst(const char *str)
{
	if (str == NULL)
                return NULL;

        STRDUP_CORE(t_malloc(len), str);
}

int *p_intarrdup(Pool pool, const int *arr)
{
	if (arr == NULL)
                return NULL;

        STRDUP_CORE(p_malloc(pool, sizeof(int) * len), arr);
}

const int *t_intarrdup(const int *arr)
{
	if (arr == NULL)
                return NULL;

        STRDUP_CORE(t_malloc(sizeof(int) * len), arr);
}

#define STRDUP_EMPTY_CORE(alloc_func, str) STMT_START { \
	if ((str) == NULL || (str)[0] == '\0')	\
                return NULL;			\
						\
	STRDUP_CORE(alloc_func, str);		\
	} STMT_END


char *p_strdup_empty(Pool pool, const char *str)
{
        STRDUP_EMPTY_CORE(p_malloc(pool, len), str);
}

const char *t_strdup_empty(const char *str)
{
        STRDUP_EMPTY_CORE(t_malloc(len), str);
}

char *p_strdup_until(Pool pool, const char *start, const char *end)
{
	size_t size;
	char *mem;

	i_assert(start <= end);

	size = (size_t) (end-start);
	i_assert(size < SSIZE_T_MAX);

	mem = p_malloc(pool, size + 1);
	memcpy(mem, start, size);
	return mem;
}

const char *t_strdup_until(const char *start, const char *end)
{
	size_t size;
	char *mem;

	i_assert(start <= end);

	size = (size_t) (end-start);
	i_assert(size < SSIZE_T_MAX);

	mem = t_malloc(size + 1);
	memcpy(mem, start, size);
	mem[size] = '\0';
	return mem;
}

static inline char *strndup_core(const char *str, size_t max_chars,
				 ALLOC_FUNC alloc, Pool pool)
{
	char *mem;
	size_t len;

	i_assert(max_chars < SSIZE_T_MAX);

	if (str == NULL)
		return NULL;

	len = 0;
	while (str[len] != '\0' && len < max_chars)
		len++;

	mem = alloc(pool, len+1);
	memcpy(mem, str, len);
	mem[len] = '\0';
	return mem;
}

char *p_strndup(Pool pool, const char *str, size_t max_chars)
{
        return strndup_core(str, max_chars, pool->malloc, pool);
}

const char *t_strndup(const char *str, size_t max_chars)
{
        return strndup_core(str, max_chars, tp_malloc, NULL);
}

char *p_strdup_printf(Pool pool, const char *format, ...)
{
	va_list args;
        char *ret;

	va_start(args, format);
        ret = p_strdup_vprintf(pool, format, args);
	va_end(args);

	return ret;
}

const char *t_strdup_printf(const char *format, ...)
{
	va_list args;
        const char *ret;

	va_start(args, format);
        ret = t_strdup_vprintf(format, args);
	va_end(args);

	return ret;
}

static inline char *
strdup_vprintf_core(const char *format, va_list args,
		    ALLOC_FUNC alloc_func, Pool pool)
{
        va_list temp_args;
        char *ret;

	if (format == NULL)
		return NULL;

	format = fix_format(format);

	VA_COPY(temp_args, args);

        ret = alloc_func(pool, printf_string_upper_bound(format, args));
	vsprintf(ret, format, args);

	va_end(temp_args);

        return ret;
}

char *p_strdup_vprintf(Pool pool, const char *format, va_list args)
{
	char *ret;

	t_push();
	ret = strdup_vprintf_core(format, args, pool->malloc, pool);
	t_pop();
	return ret;
}

const char *t_strdup_vprintf(const char *format, va_list args)
{
        return strdup_vprintf_core(format, args, tp_malloc, NULL);
}

void p_strdup_replace(Pool pool, char **dest, const char *str)
{
	p_free(pool, *dest);
        *dest = p_strdup(pool, str);
}

const char *temp_strconcat(const char *str1, va_list args,
			   size_t *ret_len)
{
	const char *str;
        char *temp;
	size_t full_len, len, bufsize;

	if (str1 == NULL)
		return NULL;

        /* put str1 to buffer */
        len = strlen(str1);
	bufsize = len <= STRCONCAT_BUFSIZE ? STRCONCAT_BUFSIZE :
		nearest_power(len+1);
        temp = t_buffer_get(bufsize);

	memcpy(temp, str1, len);
	full_len = len;

        /* put rest of the strings to buffer */
	while ((str = va_arg(args, char *)) != NULL) {
		len = strlen(str);
		if (len == 0)
			continue;

		if (bufsize < full_len+len+1) {
			bufsize = nearest_power(bufsize+len+1);
			temp = t_buffer_reget(temp, bufsize);
		}

                memcpy(temp+full_len, str, len);
		full_len += len;
	}

	temp[full_len] = '\0';
        *ret_len = full_len+1;
        return temp;
}

char *p_strconcat(Pool pool, const char *str1, ...)
{
	va_list args;
        const char *temp;
	char *ret;
        size_t len;

	va_start(args, str1);

	temp = temp_strconcat(str1, args, &len);
	if (temp == NULL)
		ret = NULL;
	else {
		ret = p_malloc(pool, len);
		memcpy(ret, temp, len);
	}

	va_end(args);
        return ret;
}

const char *t_strconcat(const char *str1, ...)
{
	va_list args;
	const char *ret;
        size_t len;

	va_start(args, str1);

	ret = temp_strconcat(str1, args, &len);
	if (ret != NULL)
		t_buffer_alloc(len);

	va_end(args);
        return ret;
}

const char *t_strcut(const char *str, char cutchar)
{
	const char *p;

	for (p = str; *p != '\0'; p++) {
		if (*p == cutchar)
                        return t_strdup_until(str, p);
	}

        return str;
}

int is_numeric(const char *str, char end_char)
{
	if (*str == '\0' || *str == end_char)
		return FALSE;

	while (*str != '\0' && *str != end_char) {
		if (!i_isdigit(*str))
			return FALSE;
		str++;
	}

	return TRUE;
}

char *str_ucase(char *str)
{
	char *p;

	for (p = str; *p != '\0'; p++)
		*p = i_toupper(*p);
        return str;
}

char *str_lcase(char *str)
{
	char *p;

	for (p = str; *p != '\0'; p++)
		*p = i_tolower(*p);
        return str;
}

char *i_strtoken(char **str, char delim)
{
	char *ret;

	if (*str == NULL || **str == '\0')
                return NULL;

	ret = *str;
	while (**str != '\0') {
		if (**str == delim) {
			**str = '\0';
                        (*str)++;
                        break;
		}
                (*str)++;
	}
        return ret;
}

void string_remove_escapes(char *str)
{
	char *dest;

	for (dest = str; *str != '\0'; str++) {
		if (*str != '\\' || str[1] == '\0')
			*dest++ = *str;
	}

	*dest = '\0';
}

int strarray_length(char *const array[])
{
	int len;

	len = 0;
	while (*array) {
		len++;
                array++;
	}
        return len;
}

int strarray_find(char *const array[], const char *item)
{
	int index;

	i_assert(item != NULL);

	for (index = 0; *array != NULL; index++, array++) {
		if (strcasecmp(*array, item) == 0)
			return index;
	}

	return -1;
}

char *const *t_strsplit(const char *data, const char *separators)
{
        char **array;
	char *str;
        size_t alloc_len, len;

        i_assert(*separators != '\0');

	len = strlen(data)+1;
	str = t_malloc(len);
	memcpy(str, data, len);

        alloc_len = 20;
        array = t_buffer_get(sizeof(const char *) * alloc_len);

	array[0] = str; len = 1;
	while (*str != '\0') {
		if (strchr(separators, *str) != NULL) {
			/* separator found */
			if (len+1 >= alloc_len) {
                                alloc_len *= 2;
				array = t_buffer_reget(array,
						       sizeof(const char *) *
						       alloc_len);
			}

                        *str = '\0';
			array[len++] = str+1;
		}

                str++;
	}
        array[len] = NULL;

	t_buffer_alloc(sizeof(const char *) * (len+1));
        return (char *const *) array;
}

const char *t_strjoin_replace(char *const args[], char separator,
			      int replacearg, const char *replacedata)
{
        const char *arg;
        char *data;
	size_t alloc_len, arg_len, full_len;
	int i;

	if (args[0] == NULL)
                return NULL;

        alloc_len = 512; full_len = 0;
	data = t_buffer_get(alloc_len);
	for (i = 0; args[i] != NULL; i++) {
		arg = i == replacearg ? replacedata : args[i];
		arg_len = strlen(arg);

		if (full_len + arg_len+1 >= alloc_len) {
			alloc_len = nearest_power(full_len + arg_len+1);
                        data = t_buffer_reget(data, alloc_len);
		}

		memcpy(data+full_len, arg, arg_len);
                full_len += arg_len;

                data[full_len++] = separator;
	}
        data[full_len-1] = '\0';

        t_buffer_alloc(full_len);
        return data;
}

static size_t dec2str_recurse(char *buffer, size_t pos, size_t size,
			      largest_t number)
{
	if (number == 0)
		return 0;

	pos = dec2str_recurse(buffer, pos, size-1, number / 10);
	if (pos < size)
		buffer[pos] = '0' + (number % 10);
	return pos + 1;
}

void dec2str(char *buffer, size_t size, largest_t number)
{
	size_t pos;

	if (size == 0)
		return;

	pos = dec2str_recurse(buffer, 0, size, number);

	if (pos == 0 && size > 1) {
		/* we wrote nothing, because number is 0 */
		buffer[0] = '0';
		pos++;
	}

	buffer[pos < size ? pos : size-1] = '\0';
}
