#ifndef __HEX_BINARY_H
#define __HEX_BINARY_H

/* Convert binary to lowercased hex digits allocating return value from
   data stack */
const char *binary_to_hex(const unsigned char *data, size_t size);

/* Convert hex to binary. data and dest may point to same value.
   Returns TRUE if successful. Returns 1 if all ok, 0 if dest buffer got full
   or -1 if data is invalid. */
int hex_to_binary(const char *data, buffer_t *dest);

#endif
