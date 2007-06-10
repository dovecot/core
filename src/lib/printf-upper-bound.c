/*
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
#include "printf-format-fix.h"
#include "printf-upper-bound.h"

typedef union  _GDoubleIEEE754  GDoubleIEEE754;
#define G_IEEE754_DOUBLE_BIAS   (1023)
/* multiply with base2 exponent to get base10 exponent (nomal numbers) */
#define G_LOG_2_BASE_10         (0.30102999566398119521)

#ifndef WORDS_BIGENDIAN
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
#else
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
#endif

typedef struct
{
  unsigned int min_width;
  unsigned int precision;
  int alternate_format, locale_grouping;
  int add_space, add_sign, possible_sign, seen_precision;
  int mod_long, mod_extra_long;
} PrintfArgSpec;

#if (SIZEOF_LONG > 4) || (SIZEOF_VOID_P > 4)
#  define HONOUR_LONGS 1
#else
#  define HONOUR_LONGS 0
#endif

size_t printf_string_upper_bound(const char **format_p, va_list args)
{
  const char *format = *format_p;
  size_t len = 1;
  bool fix_format = FALSE;

  if (!format)
    return len;

  while (*format)
    {
      if (*format++ != '%')
        len += 1;
      else if (*format == 's')
	{
	  /* most commonly used modifier, optimize for it */
	  const char *v_string = va_arg (args, const char*);
	  if (!v_string)
	    len += 8; /* hold "(null)" */
	  else
	    len += strlen(v_string);
	}
      else if (*format == 'u')
	{
	  /* second most commonly used modifier */
	  (void) va_arg (args, unsigned int);
	  len += MAX_INT_STRLEN;
	}
      else
        {
          PrintfArgSpec spec;
          bool seen_l = FALSE, conv_done = FALSE;
          unsigned int conv_len = 0;

          memset(&spec, 0, sizeof(spec));
          do
            {
              char c = *format++;
              switch (c)
                {
                  GDoubleIEEE754 u_double;
                  unsigned int v_uint;
                  int v_int;
                  const char *v_string;

                  /* beware of positional parameters
                   */
                case '$':
                  i_panic("unable to handle positional parameters (%%n$)");
                  break;

                  /* parse flags
                   */
                case '#':
                  spec.alternate_format = TRUE;
                  break;
                case '0':
                case '-':
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
                          v_int = - v_int;
                      spec.min_width = I_MAX ((int)spec.min_width, v_int);
                    }
                  break;

                  /* parse type modifiers
                   */
                case 'h':
		  /* ignore */
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
                  spec.mod_long = TRUE;
                  spec.mod_extra_long = TRUE;
                  break;

                  /* parse output conversions
                   */
                case '%':
                  conv_len += 1;
                  break;
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
#if SIZEOF_LONG_LONG > 0
                      (void) va_arg (args, long long);
#else
		      i_panic("mod_extra_long not supported");
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
                    i_panic("unable to handle long double");
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
                case 'c':
                  conv_len += spec.mod_long ? MB_LEN_MAX : 1;
                  (void) va_arg (args, int);
                  break;
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
                    i_panic("unable to handle wide char strings");
                  break;
                case 'p':
                  spec.alternate_format = TRUE;
                  conv_len += 10;
                  if (HONOUR_LONGS)
                    conv_len *= 2;
		  conv_done = TRUE;
		  (void) va_arg (args, void*);
                  break;
		case 'm':
		  /* %m, replace it with strerror() later */
		  conv_len += strlen(strerror(errno)) + 256;
		  fix_format = TRUE;
		  break;

                  /* handle invalid cases
                   */
                case '\000':
                  /* no conversion specification, bad bad */
		  i_panic("Missing conversion specifier");
                  break;
                default:
                  i_panic("unable to handle `%c' while parsing format", c);
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

  if (fix_format)
    (void)printf_format_fix(format_p);
  return len;
}
