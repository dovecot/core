#ifndef NTLM_ENCRYPT_H
#define NTLM_ENCRYPT_H

const unsigned char *
lm_hash(const char *passwd, unsigned char hash[LM_HASH_SIZE]);

const unsigned char *
ntlm_v1_hash(const char *passwd, unsigned char hash[NTLMSSP_HASH_SIZE]);

void ntlmssp_v1_response(const unsigned char *hash,
			 const unsigned char *challenge,
			 unsigned char response[NTLMSSP_RESPONSE_SIZE]);

void ntlmssp2_response( const unsigned char *hash,
			const unsigned char *server_challenge,
			const unsigned char *client_challenge,
			unsigned char response[NTLMSSP_RESPONSE_SIZE]);

void ntlmssp_v2_response(const char *user, const char *target,
			 const unsigned char *hash_v1,
			 const unsigned char *challenge,
			 const unsigned char *blob, size_t blob_size,
			 unsigned char response[NTLMSSP_V2_RESPONSE_SIZE]);

#endif
