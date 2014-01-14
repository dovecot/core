#ifndef IOSTREAM_LZ4_H
#define IOSTREAM_LZ4_H

/*
   Dovecot's LZ4 compressed files contain:

   IOSTREAM_LZ4_HEADER
   n x (4 byte big-endian: compressed chunk length, compressed chunk)
*/

#define IOSTREAM_LZ4_MAGIC "Dovecot-LZ4\x0d\x2a\x9b\xc5"
#define IOSTREAM_LZ4_MAGIC_LEN (sizeof(IOSTREAM_LZ4_MAGIC)-1)

struct iostream_lz4_header {
	unsigned char magic[IOSTREAM_LZ4_MAGIC_LEN];
	/* OSTREAM_LZ4_CHUNK_SIZE in big-endian */
	unsigned char max_uncompressed_chunk_size[4];
};

/* How large chunks we're buffering into memory before compressing them */
#define OSTREAM_LZ4_CHUNK_SIZE (1024*64)
/* How large chunks we allow in input data before returning a failure.
   This must be at least OSTREAM_LZ4_CHUNK_SIZE, but for future compatibility
   should be somewhat higher (but not too high to avoid wasting memory for
   corrupted files). */
#define ISTREAM_LZ4_CHUNK_SIZE (1024*1024)

#define IOSTREAM_LZ4_CHUNK_PREFIX_LEN 4 /* big-endian size of chunk */

#endif
