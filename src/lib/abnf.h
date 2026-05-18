#ifndef ABNF_H
#define ABNF_H

/* RFC 5234 core rules that match a single character only. */

#define ABNF_IS(name, chr) static inline bool abnf_is_##name(char ch) \
{ return ch == (chr); }

/* bool abnf_is_cr(char ch) and so on */
ABNF_IS(cr, '\r')
ABNF_IS(lf, '\n')
ABNF_IS(dquote, '"')
ABNF_IS(htab, '\t')
ABNF_IS(sp, ' ')

#undef ABNF_IS

static inline bool abnf_is_ascii_ctrl(char ch)
{
	return (unsigned char)ch <= 0x1f || ch == 0x7f;
}

static inline bool abnf_is_wsp(char ch)
{
	return abnf_is_sp(ch) || abnf_is_htab(ch);
}

static inline bool abnf_is_ascii_alpha(char ch)
{
	return ((ch >= 'A' && ch <= 'Z') ||
		(ch >= 'a' && ch <= 'z'));
}

static inline bool abnf_is_ascii_char(char ch)
{
	return ch >= 0x01 && (unsigned char)ch <= 0x7f;
}

static inline bool abnf_is_ascii_printable_char(char ch)
{
	return ch >= 0x20 && ch <= 0x7e;
}

static inline bool abnf_is_ascii_visible_char(char ch)
{
	return ch >= 0x21 && ch <= 0x7e;
}

static inline bool abnf_is_bit(char ch)
{
	return ch == '0' || ch == '1';
}

static inline bool abnf_is_digit(char ch)
{
	return ch >= '0' && ch <= '9';
}

static inline bool abnf_is_hexdig(char ch)
{
	/* This intentionally loosens RFC 5234 to accept lowercase too */
	return abnf_is_digit(ch) ||
	       (ch >= 'A' && ch <= 'F') ||
	       (ch >= 'a' && ch <= 'f');
}

#define ABNF_CONTAINS_BODY(predicate) \
	for (; *str != '\0'; ++str) \
		if (predicate(*str)) \
			return TRUE; \
	return FALSE;

#define ABNF_IS_ONLY_BODY(predicate) \
	for (; *str != '\0'; ++str) \
		if (!(predicate(*str))) \
			return FALSE; \
	return TRUE;

#define ABNF_CONTAINS(name, predicate) \
static inline bool name(const char *str) { ABNF_CONTAINS_BODY(predicate) }
static inline bool abnf_contains(const char *str, bool (*predicate)(char))
{
	ABNF_CONTAINS_BODY(predicate)
}
#define ABNF_CONTAINS_GEN(name) ABNF_CONTAINS(abnf_contains_##name, abnf_is_##name)

/* bool abnf_contains_cr(const char *str) and so on */
ABNF_CONTAINS_GEN(cr)
ABNF_CONTAINS_GEN(lf)
ABNF_CONTAINS_GEN(dquote)
ABNF_CONTAINS_GEN(htab)
ABNF_CONTAINS_GEN(sp)
ABNF_CONTAINS_GEN(ascii_ctrl)
ABNF_CONTAINS_GEN(wsp)
ABNF_CONTAINS_GEN(ascii_alpha)
ABNF_CONTAINS_GEN(ascii_char)
ABNF_CONTAINS_GEN(ascii_printable_char)
ABNF_CONTAINS_GEN(ascii_visible_char)
ABNF_CONTAINS_GEN(bit)
ABNF_CONTAINS_GEN(digit)
ABNF_CONTAINS_GEN(hexdig)

#undef ABNF_CONTAINS_BODY
#undef ABNF_CONTAINS_GEN
#undef ABNF_CONTAINS

#define ABNF_IS_ONLY(name, predicate) \
static inline bool name(const char *str) { ABNF_IS_ONLY_BODY(predicate) }
static inline bool abnf_is_only(const char *str, bool (*predicate)(char))
{
	ABNF_IS_ONLY_BODY(predicate)
}
#define ABNF_IS_ONLY_GEN(name)  ABNF_IS_ONLY(abnf_is_only_##name,   abnf_is_##name)

/* bool abnf_is_only_cr(const char *str) and so on */
ABNF_IS_ONLY_GEN(cr)
ABNF_IS_ONLY_GEN(lf)
ABNF_IS_ONLY_GEN(dquote)
ABNF_IS_ONLY_GEN(htab)
ABNF_IS_ONLY_GEN(sp)
ABNF_IS_ONLY_GEN(ascii_ctrl)
ABNF_IS_ONLY_GEN(wsp)
ABNF_IS_ONLY_GEN(ascii_alpha)
ABNF_IS_ONLY_GEN(ascii_char)
ABNF_IS_ONLY_GEN(ascii_printable_char)
ABNF_IS_ONLY_GEN(ascii_visible_char)
ABNF_IS_ONLY_GEN(bit)
ABNF_IS_ONLY_GEN(digit)
ABNF_IS_ONLY_GEN(hexdig)

#undef ABNF_IS_ONLY_BODY
#undef ABNF_IS_ONLY_GEN
#undef ABNF_IS_ONLY

#endif
