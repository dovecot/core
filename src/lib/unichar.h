#ifndef __UNICHAR_H
#define __UNICHAR_H

typedef uint32_t unichar_t;

extern const char *const uni_utf8_skip;

/* Returns number of characters in a NUL-terminated unicode string */
unsigned int uni_strlen(const unichar_t *str);
/* Translates UTF-8 input to UCS-4 output. Returns 0 if ok, -1 if input was
   invalid */
int uni_utf8_to_ucs4(const char *input, buffer_t *output);
/* Translates UCS-4 input to UTF-8 output. */
void uni_ucs4_to_utf8(const unichar_t *input, size_t len, buffer_t *output);

/* Returns the next UTF-8 character, or (unichar_t)-1 for invalid input and
   (unichar_t)-2 for incomplete trailing character. */
unichar_t uni_utf8_get_char(const char *input);
unichar_t uni_utf8_get_char_len(const unsigned char *input, size_t max_len);
/* Returns UTF-8 string length with maximum input size. */
unsigned int uni_utf8_strlen_n(const void *input, size_t size);

#define uni_utf8_next_char(p) \
	((p) + uni_utf8_skip[*(const uint8_t *)(p)])

#endif
