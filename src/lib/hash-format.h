#ifndef HASH_FORMAT_H
#define HASH_FORMAT_H

struct hash_format;

/* Initialize formatting hash. Format can contain text with %{sha1} style
   variables. Each hash hash can be also truncated by specifying the number
   of bits to truncate to, such as %{sha1:80}. */
int hash_format_init(const char *format_string, struct hash_format **format_r,
		     const char **error_r);
/* Add more data to hash. */
void hash_format_loop(struct hash_format *format,
		      const void *data, size_t size);
/* Write the hash into given string and free used memory. */
void hash_format_deinit(struct hash_format **format, string_t *dest);
/* Free used memory without writing to string. */
void hash_format_deinit_free(struct hash_format **format);

#endif
