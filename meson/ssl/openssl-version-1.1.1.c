#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x10101000L
#error "fail-compile"
#endif
