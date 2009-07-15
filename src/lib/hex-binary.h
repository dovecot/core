#ifndef HEX_BINARY_H
#define HEX_BINARY_H

/* Convert binary to hex digits allocating return value from data stack */
const char *binary_to_hex(const unsigned char *data, size_t size);
const char *binary_to_hex_ucase(const unsigned char *data, size_t size);

void binary_to_hex_append(string_t *dest, const unsigned char *data,
			  size_t size);

/* Convert hex to binary. data and dest may point to same value.
   Returns 0 if all ok, -1 if data is invalid. */
int hex_to_binary(const char *data, buffer_t *dest);

#endif
