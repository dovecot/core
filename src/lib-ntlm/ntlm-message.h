#ifndef NTLM_MESSAGE_H
#define NTLM_MESSAGE_H

const struct ntlmssp_challenge *
ntlmssp_create_challenge(pool_t pool, const struct ntlmssp_request *request,
			 size_t *size);

bool ntlmssp_check_request(const struct ntlmssp_request *request,
			   size_t data_size, const char **error);
bool ntlmssp_check_response(const struct ntlmssp_response *response,
			    size_t data_size, const char **error);

#endif
