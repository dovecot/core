#ifndef __HEX_BINARY_H
#define __HEX_BINARY_H

/* Convert binary to lowercased hex digits allocating return value from
   temporary memory pool */
const char *binary_to_hex(const unsigned char *data, unsigned int size);

/* Convert hex to binary. data and dest may point to same value.
   Returns TRUE if successful. Returns number of bytes written to dest,
   or -1 if error occured. Make sure dest is at least half the size of
   strlen(data). */
int hex_to_binary(const char *data, unsigned char *dest);

#endif
