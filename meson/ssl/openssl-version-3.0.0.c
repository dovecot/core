#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#error "fail-compile"
#endif
