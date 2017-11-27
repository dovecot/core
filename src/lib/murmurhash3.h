/*
  MurmurHash3 was written by Austin Appleby, and is placed in the public
  domain. The author hereby disclaims copyright to this source code.


  Adapted for dovecot by Aki Tuomi <aki.tuomi@dovecot.fi> 2017-11-27
*/
#ifndef MURMURHASH3_H
#define MURMURHASH3_H

#define MURMURHASH3_32_RESULTBYTES (sizeof(uint32_t))
#ifdef _LP64
#define MURMURHASH3_128_RESULTBYTES (sizeof(uint64_t)*2)
#else
#define MURMURHASH3_128_RESULTBYTES (sizeof(uint32_t)*4)
#endif

/* You should use random seed */
void murmurhash3_32(const void * key, size_t len, uint32_t seed,
		    unsigned char out[STATIC_ARRAY MURMURHASH3_32_RESULTBYTES]);
void murmurhash3_128(const void * key, size_t len, uint32_t seed,
		     unsigned char out[STATIC_ARRAY MURMURHASH3_128_RESULTBYTES]);
#endif
