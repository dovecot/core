
#include "lib.h"
#include "hex-binary.h"
#include "password-scheme.h"

#include "ntlm.h"

const char *password_generate_ntlm(const char *plaintext)
{
	unsigned char hash[16];

	ntlm_v1_hash(plaintext, hash);

	return binary_to_hex_ucase(hash, sizeof(hash));
}
