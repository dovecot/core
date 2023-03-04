#ifndef MECH_DIGEST_MD5_PRIVATE_H
#define MECH_DIGEST_MD5_PRIVATE_H

#include "auth-request.h"

void mech_digest_test_set_nonce(struct auth_request *auth_request,
				const char *nonce);

#endif
