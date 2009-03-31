#ifndef STR_FIND_H
#define STR_FIND_H

struct str_find_context;

struct str_find_context *str_find_init(pool_t pool, const char *key);
void str_find_deinit(struct str_find_context **ctx);

/* Returns TRUE if key is found. It's possible to send the data in arbitrary
   blocks and have the key still match. */
bool str_find_more(struct str_find_context *ctx,
		   const unsigned char *data, size_t size);
/* After str_find_more() has returned TRUE, this function returns the end
   position in the previous data block where the key had matched. */
size_t str_find_get_match_end_pos(struct str_find_context *ctx);
/* Reset input data. The next str_find_more() call won't try to match the key
   to earlier data. */
void str_find_reset(struct str_find_context *ctx);

#endif
