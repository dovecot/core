static void
Hi(const struct hash_method *hmethod, const unsigned char *str, size_t str_size,
   const unsigned char *salt, size_t salt_size, unsigned int i,
   unsigned char *result)
{
	struct hmac_context ctx;
	unsigned char U[hmethod->digest_size];
	unsigned int j, k;

	/* Calculate U1 */
	hmac_init(&ctx, str, str_size, hmethod);
	hmac_update(&ctx, salt, salt_size);
	hmac_update(&ctx, "\0\0\0\1", 4);
	hmac_final(&ctx, U);

	memcpy(result, U, hmethod->digest_size);

	/* Calculate U2 to Ui and Hi */
	for (j = 2; j <= i; j++) {
		hmac_init(&ctx, str, str_size, hmethod);
		hmac_update(&ctx, U, sizeof(U));
		hmac_final(&ctx, U);
		for (k = 0; k < hmethod->digest_size; k++)
			result[k] ^= U[k];
	}
}
