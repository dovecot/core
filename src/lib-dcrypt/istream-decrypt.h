#ifndef ISTREAM_DECRYPT_H
#define ISTREAM_DECRYPT_H

struct dcrypt_private_key;
struct dcrypt_context_symmetric;

enum decrypt_istream_format {
	DECRYPT_FORMAT_V1,
	DECRYPT_FORMAT_V2
};

/* Look for a private key for a specified public key digest and set it to
   priv_key_r. Returns 1 if ok, 0 if key doesn't exist, -1 on internal error.

   Note that the private key will be unreferenced when the istream is
   destroyed. If the callback is returning a persistent key, it must reference
   the key first. (This is required, because otherwise a key newly created by
   the callback couldn't be automatically freed.) */
typedef int
i_stream_decrypt_get_key_callback_t(const char *pubkey_digest,
				    struct dcrypt_private_key **priv_key_r,
				    const char **error_r, void *context);

struct istream *
i_stream_create_decrypt(struct istream *input,
			struct dcrypt_private_key *priv_key);

/* create stream for reading plain encrypted data with no header or MAC.
   do not call dcrypt_ctx_sym_init
 */
struct istream *
i_stream_create_sym_decrypt(struct istream *input,
			    struct dcrypt_context_symmetric *ctx);


/* Decrypt the istream. When a private key is needed, the callback will be
   called. This allows using multiple private keys for different mails. */
struct istream *
i_stream_create_decrypt_callback(struct istream *input,
				 i_stream_decrypt_get_key_callback_t *callback,
				 void *context);

enum decrypt_istream_format
i_stream_encrypt_get_format(const struct istream *input);
enum io_stream_encrypt_flags
i_stream_encrypt_get_flags(const struct istream *input);

#endif
