#ifndef __NTLM_MESSAGE_H__
#define __NTLM_MESSAGE_H__

const struct ntlmssp_challenge *
ntlmssp_create_challenge(pool_t pool, const struct ntlmssp_request *request,
			 size_t *size);

int ntlmssp_check_request(const struct ntlmssp_request *request,
			  size_t data_size, const char **error);
int ntlmssp_check_response(const struct ntlmssp_response *response,
			   size_t data_size, const char **error);

#endif	/* __NTLM_MESSAGE_H__ */
