#ifndef NTLM_DES_H
#define NTLM_DES_H

void deshash(unsigned char *dst, const unsigned char *key,
	     const unsigned char *src);

#endif
