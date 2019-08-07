#ifndef JSON_SYNTAX_H
#define JSON_SYNTAX_H

#include "unichar.h"

extern const unsigned char json_uchar_char_mask;
extern const unsigned char json_control_char_mask;
extern const unsigned char json_ws_char_mask;
extern const unsigned char json_digit_char_mask;

extern const unsigned char json_char_lookup[128];

static inline bool json_unichar_is_uchar(unichar_t ch)
{
	if (ch > 0x7F)
		return (ch <= 0x10FFFF);
	return ((json_char_lookup[ch] & json_uchar_char_mask) != 0);
}

static inline bool json_unichar_is_control(unichar_t ch)
{
	if (ch > 0x7F)
		return FALSE;
	return ((json_char_lookup[ch] & json_control_char_mask) != 0);
}

static inline bool json_unichar_is_ws(unichar_t ch)
{
	if (ch > 0x7F)
		return FALSE;
	return ((json_char_lookup[ch] & json_ws_char_mask) != 0);
}

static inline bool json_unichar_is_digit(unichar_t ch)
{
	if (ch > 0x7F)
		return FALSE;
	return ((json_char_lookup[ch] & json_digit_char_mask) != 0);
}

#endif
