#ifndef __NTLM_DES_H__
#define __NTLM_DES_H__

unsigned char * deshash(unsigned char *dst, const unsigned char *key,
			const unsigned char *src);

#endif	/* __NTLM_DES_H__ */
