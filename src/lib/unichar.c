/* Copyright (C) 2005 Timo Sirainen */

/* Contains code from GLIB:
 *
 * Copyright (C) 1999 Tom Tromey
 * Copyright (C) 2000 Red Hat, Inc.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.	 See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include "lib.h"
#include "buffer.h"
#include "unichar.h"

#define UTF8_LENGTH(Char)              \
  ((Char) < 0x80 ? 1 :                 \
   ((Char) < 0x800 ? 2 :               \
    ((Char) < 0x10000 ? 3 :            \
     ((Char) < 0x200000 ? 4 :          \
      ((Char) < 0x4000000 ? 5 : 6)))))

static const char utf8_skip_data[256] = {
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
  2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,2,
  3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,3,4,4,4,4,4,4,4,4,5,5,5,5,6,6,1,1
};

const char *const uni_utf8_skip = utf8_skip_data;

unsigned int uni_strlen(const unichar_t *str)
{
	unsigned int len = 0;

	for (len = 0; str[len] != 0; len++) ;

	return len;
}

unichar_t uni_utf8_get_char(const char *input)
{
	return uni_utf8_get_char_len((const unsigned char *)input, (size_t)-1);
}

unichar_t uni_utf8_get_char_len(const unsigned char *input, size_t max_len)
{
  unsigned int i, len;
  unichar_t wc = *input;

  i_assert(max_len > 0);

  if (wc < 0x80)
    {
      return wc;
    }
  else if (wc < 0xc0)
    {
      return (unichar_t)-1;
    }
  else if (wc < 0xe0)
    {
      len = 2;
      wc &= 0x1f;
    }
  else if (wc < 0xf0)
    {
      len = 3;
      wc &= 0x0f;
    }
  else if (wc < 0xf8)
    {
      len = 4;
      wc &= 0x07;
    }
  else if (wc < 0xfc)
    {
      len = 5;
      wc &= 0x03;
    }
  else if (wc < 0xfe)
    {
      len = 6;
      wc &= 0x01;
    }
  else
    {
      return (unichar_t)-1;
    }

  if (max_len != (size_t)-1 && len > max_len)
    {
      for (i = 1; i < max_len; i++)
	{
	  if ((input[i] & 0xc0) != 0x80)
	    return (unichar_t)-1;
	}
      return (unichar_t)-2;
    }

  for (i = 1; i < len; ++i)
    {
      if ((input[i] & 0xc0) != 0x80)
	{
	  if (input[i] != '\0')
	    return (unichar_t)-1;
	  else
	    return (unichar_t)-2;
	}

      wc <<= 6;
      wc |= (input[i] & 0x3f);
    }

  if (UTF8_LENGTH(wc) != len)
    return (unichar_t)-1;
  
  return wc;
}

/**
 * g_unichar_to_utf8:
 * @c: a ISO10646 character code
 * @outbuf: output buffer, must have at least 6 bytes of space.
 *       If %NULL, the length will be computed and returned
 *       and nothing will be written to @outbuf.
 * 
 * Converts a single character to UTF-8.
 * 
 * Return value: number of bytes written
 **/
static int
g_unichar_to_utf8(unichar_t c, char *outbuf)
{
  unsigned int len = 0;
  int first;
  int i;

  if (c < 0x80)
    {
      first = 0;
      len = 1;
    }
  else if (c < 0x800)
    {
      first = 0xc0;
      len = 2;
    }
  else if (c < 0x10000)
    {
      first = 0xe0;
      len = 3;
    }
   else if (c < 0x200000)
    {
      first = 0xf0;
      len = 4;
    }
  else if (c < 0x4000000)
    {
      first = 0xf8;
      len = 5;
    }
  else
    {
      first = 0xfc;
      len = 6;
    }

  if (outbuf)
    {
      for (i = len - 1; i > 0; --i)
	{
	  outbuf[i] = (c & 0x3f) | 0x80;
	  c >>= 6;
	}
      outbuf[0] = c | first;
    }

  return len;
}

int uni_utf8_to_ucs4(const char *input, buffer_t *output)
{
	unichar_t chr;

	while (*input != '\0') {
		chr = uni_utf8_get_char(input);
		if (chr & 0x80000000) {
			/* invalid input */
			return -1;
		}
                input = uni_utf8_next_char(input);

		buffer_append(output, &chr, sizeof(chr));
	}
	return 0;
}

void uni_ucs4_to_utf8(const unichar_t *input, size_t len, buffer_t *output)
{
	void *buf;
	int char_len;

	for (; *input != '\0' && len > 0; input++, len--) {
		buf = buffer_append_space_unsafe(output, 6);
		char_len = g_unichar_to_utf8(*input, buf);
		buffer_set_used_size(output, output->used - 6 + char_len);
	}
}

unsigned int uni_utf8_strlen_n(const void *input, size_t size)
{
	const uint8_t *data = (const uint8_t *)input;
	unsigned int len = 0;
	size_t i;

	for (i = 0; i < size && data[i] != '\0'; ) {
		i += uni_utf8_skip[data[i]];
		if (i > size)
			break;
		len++;
	}
	return len;
}
