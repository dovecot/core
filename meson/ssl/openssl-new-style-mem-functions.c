#include <openssl/ssl.h>
int CRYPTO_set_mem_functions(
	void *(*m) (size_t, const char *, int),
	void *(*r) (void *, size_t, const char *, int),
	void (*f) (void *, const char *, int));

int main(void) {
	return 0;
}
