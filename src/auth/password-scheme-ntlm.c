
#include "lib.h"
#include "hex-binary.h"
#include "password-scheme.h"

#include "ntlm.h"

const char *password_generate_lm(const char *pw)
{
	unsigned char hash[LM_HASH_SIZE];

	lm_hash(pw, hash);

	return binary_to_hex_ucase(hash, sizeof(hash));
}

const char *password_generate_ntlm(const char *pw)
{
	unsigned char hash[NTLMSSP_HASH_SIZE];

	ntlm_v1_hash(pw, hash);

	return binary_to_hex_ucase(hash, sizeof(hash));
}
