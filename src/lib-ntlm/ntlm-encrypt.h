#ifndef __NTLM_ENCRYPT__
#define __NTLM_ENCRYPT__

const unsigned char *
ntlm_v1_hash(const char *passwd, unsigned char hash[NTLMSSP_HASH_SIZE]);

void ntlmssp_v1_response(const unsigned char *hash,
			 const unsigned char *challenge,
			 unsigned char response[NTLMSSP_RESPONSE_SIZE]);

void ntlmssp_v2_response(const char *user, const char *target,
			 const unsigned char *hash_v1,
			 const unsigned char *challenge,
			 const unsigned char *blob, size_t blob_size,
			 unsigned char response[NTLMSSP_V2_RESPONSE_SIZE]);

#endif	/* __NTLM_ENCRYPT__ */
