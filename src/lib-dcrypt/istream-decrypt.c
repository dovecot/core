/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "randgen.h"
#include "safe-memset.h"
#include "hash-method.h"
#include "sha2.h"
#include "dcrypt.h"
#include "istream.h"
#include "istream-decrypt.h"
#include "istream-private.h"
#include "dcrypt-iostream.h"

#include "hex-binary.h"

#include <arpa/inet.h>

#define ISTREAM_DECRYPT_READ_FIRST 15

struct decrypt_istream {
	struct istream_private istream;
	buffer_t *buf;
	bool symmetric;

	i_stream_decrypt_get_key_callback_t *key_callback;
	void *key_context;

	struct dcrypt_private_key *priv_key;
	bool initialized;
	bool finalized;
	bool use_mac;

	uoff_t ftr, pos;
	enum io_stream_encrypt_flags flags;

	/* original iv, in case seeking is done, future feature */
	unsigned char *iv;  

	struct dcrypt_context_symmetric *ctx_sym;
	struct dcrypt_context_hmac *ctx_mac;

	enum decrypt_istream_format format;
};

static void i_stream_decrypt_reset(struct decrypt_istream *dstream)
{
	dstream->finalized = FALSE;
	dstream->use_mac = FALSE;

	dstream->ftr = 0;
	dstream->pos = 0;
	dstream->flags = 0;

	if (!dstream->symmetric) {
		dstream->initialized = FALSE;
		if (dstream->ctx_sym != NULL)
			dcrypt_ctx_sym_destroy(&dstream->ctx_sym);
		if (dstream->ctx_mac != NULL)
			dcrypt_ctx_hmac_destroy(&dstream->ctx_mac);
	}
	i_free(dstream->iv);
	dstream->format = DECRYPT_FORMAT_V1;
}

enum decrypt_istream_format
i_stream_encrypt_get_format(const struct istream *input)
{
	return ((const struct decrypt_istream*)input->real_stream)->format;
}

enum io_stream_encrypt_flags
i_stream_encrypt_get_flags(const struct istream *input)
{
	return ((const struct decrypt_istream*)input->real_stream)->flags;
}

static ssize_t
i_stream_decrypt_read_header_v1(struct decrypt_istream *stream,
				const unsigned char *data, size_t mlen)
{
	const char *error = NULL;
	size_t keydata_len = 0;
	uint16_t len;
	int ec, i = 0;

	const unsigned char *digest_pos = NULL, *key_digest_pos = NULL,
		*key_ct_pos = NULL;
	size_t pos = sizeof(IOSTREAM_CRYPT_MAGIC);
	size_t digest_len = 0, key_ct_len = 0, key_digest_size = 0;

	buffer_t ephemeral_key;
	buffer_t *secret = t_buffer_create(256);
	buffer_t *key = t_buffer_create(256);

	if (mlen < 2)
		return 0;
	keydata_len = be16_to_cpu_unaligned(data);
	if (mlen-2 < keydata_len) {
		/* try to read more */
		return 0;
	}

	data+=2;
	mlen-=2;

	while (i < 4 && mlen > 2) {
		memcpy(&len, data, 2);
		len = ntohs(len);
		if (len == 0 || len > mlen-2)
			break;
		data += 2;
		mlen -= 2;
		pos += 2;

		switch(i++) {
		case 0:
			buffer_create_from_const_data(&ephemeral_key,
						      data, len);
			break;
		case 1:
			/* public key id */
			digest_pos = data;
			digest_len = len;
			break;
		case 2:
			/* encryption key digest */
			key_digest_pos = data;
			key_digest_size = len;
			break;
		case 3:
			/* encrypted key data */
			key_ct_pos = data;
			key_ct_len = len;
			break;
		}
		pos += len;
		data += len;
		mlen -= len;
	}

	if (i < 4) {
		io_stream_set_error(&stream->istream.iostream,
				    "Invalid or corrupted header");
		/* was it consumed? */
		stream->istream.istream.stream_errno =
			mlen > 2 ? EINVAL : EPIPE;
		return -1;
	}

	/* we don't have a private key */
	if (stream->priv_key == NULL) {
		/* see if we can get one */
		if (stream->key_callback != NULL) {
			const char *key_id =
				binary_to_hex(digest_pos, digest_len);
			int ret = stream->key_callback(key_id,
				&stream->priv_key, &error, stream->key_context);
			if (ret < 0) {
				io_stream_set_error(&stream->istream.iostream,
						    "Private key not available: %s",
						    error);
				return -1;
			}
			if (ret == 0) {
				io_stream_set_error(&stream->istream.iostream,
						    "Private key not available");
				return -1;
			}
		} else {
			io_stream_set_error(&stream->istream.iostream,
					    "Private key not available");
			return -1;
		}
	}

	buffer_t *check = t_buffer_create(32);

	if (!dcrypt_key_id_private_old(stream->priv_key, check, &error)) {
		io_stream_set_error(&stream->istream.iostream,
				    "Cannot get public key hash: %s", error);
		return -1;
	} else {
		if (memcmp(digest_pos, check->data,
			   I_MIN(digest_len,check->used)) != 0) {
			io_stream_set_error(&stream->istream.iostream,
					    "Private key not available");
			return -1;
		}
	}

	/* derive shared secret */
	if (!dcrypt_ecdh_derive_secret_local(stream->priv_key,
		&ephemeral_key, secret, &error)) {
		io_stream_set_error(&stream->istream.iostream,
				    "Cannot perform ECDH: %s", error);
		return -1;
	}

	/* run it thru SHA256 once */
	const struct hash_method *hash = &hash_method_sha256;
	unsigned char hctx[hash->context_size];
	unsigned char hres[hash->digest_size];
	hash->init(hctx);
	hash->loop(hctx, secret->data, secret->used);
	hash->result(hctx, hres);
	safe_memset(buffer_get_modifiable_data(secret, 0), 0, secret->used);

	/* NB! The old code was broken and used this kind of IV - it is not
	   correct, but we need to stay compatible with old data */

	/* use it to decrypt the actual encryption key */
	struct dcrypt_context_symmetric *dctx;
	if (!dcrypt_ctx_sym_create("aes-256-ctr", DCRYPT_MODE_DECRYPT,
				   &dctx, &error)) {
		io_stream_set_error(&stream->istream.iostream,
				    "Key decryption error: %s", error);
		return -1;
	}

	ec = 0;
	dcrypt_ctx_sym_set_iv(dctx, (const unsigned char*)
		"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0", 16);
	dcrypt_ctx_sym_set_key(dctx, hres, hash->digest_size);
	if (!dcrypt_ctx_sym_init(dctx, &error) ||
	    !dcrypt_ctx_sym_update(dctx, key_ct_pos, key_ct_len, key, &error) ||
	    !dcrypt_ctx_sym_final(dctx, key, &error)) {
		io_stream_set_error(&stream->istream.iostream,
				    "Key decryption error: %s", error);
		ec = -1;
	}
	dcrypt_ctx_sym_destroy(&dctx);

	if (ec != 0) {
		io_stream_set_error(&stream->istream.iostream,
				    "Key decryption error: %s", error);
		return -1;
	}

	/* see if we got the correct key */
	hash->init(hctx);
	hash->loop(hctx, key->data, key->used);
	hash->result(hctx, hres);

	if (key_digest_size != sizeof(hres)) {
		io_stream_set_error(&stream->istream.iostream,
				    "Key decryption error: "
				    "invalid digest length");
		return -1;
	}
	if (memcmp(hres, key_digest_pos, sizeof(hres)) != 0) {
		io_stream_set_error(&stream->istream.iostream,
				    "Key decryption error: "
				    "decrypted key is invalid");
		return -1;
	}

	/* prime context with key */
	if (!dcrypt_ctx_sym_create("aes-256-ctr", DCRYPT_MODE_DECRYPT,
				   &stream->ctx_sym, &error)) {
		io_stream_set_error(&stream->istream.iostream,
				    "Decryption context create error: %s",
				    error);
		return -1;
	}

	/* Again, old code used this IV, so we have to use it too */
	dcrypt_ctx_sym_set_iv(stream->ctx_sym, (const unsigned char*)
		"\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0\x0", 16);
	dcrypt_ctx_sym_set_key(stream->ctx_sym, key->data, key->used);

	safe_memset(buffer_get_modifiable_data(key, 0), 0, key->used);

	if (!dcrypt_ctx_sym_init(stream->ctx_sym, &error)) {
		io_stream_set_error(&stream->istream.iostream,
				    "Decryption init error: %s", error);
		return -1;
	}

	stream->use_mac = FALSE;
	stream->initialized = TRUE;
	/* now we are ready to decrypt stream */

	return sizeof(IOSTREAM_CRYPT_MAGIC) + 1 + 2 + keydata_len;
}

static bool
get_msb32(const unsigned char **_data, const unsigned char *end,
	  uint32_t *num_r)
{
	const unsigned char *data = *_data;
	if (end-data < 4)
		return FALSE;
	*num_r = be32_to_cpu_unaligned(data);
	*_data += 4;
	return TRUE;
}

static bool
i_stream_decrypt_der(const unsigned char **_data, const unsigned char *end,
		     const char **str_r)
{
	const unsigned char *data = *_data;
	unsigned int len;

	if (end-data < 2)
		return FALSE;
	/* get us DER encoded length */
	if ((data[1] & 0x80) != 0) {
		/* two byte length */
		if (end-data < 3)
			return FALSE;
		len = ((data[1] & 0x7f) << 8) + data[2] + 3;
	} else {
		len = data[1] + 2;
	}
	if ((size_t)(end-data) < len)
		return FALSE;
	*str_r = dcrypt_oid2name(data, len, NULL);
	*_data += len;
	return TRUE;
}

static ssize_t
i_stream_decrypt_key(struct decrypt_istream *stream, const char *malg,
		     unsigned int rounds, const unsigned char *data,
		     const unsigned char *end, buffer_t *key, size_t key_len)
{
	const char *error;
	enum dcrypt_key_type ktype;
	int keys;
	bool have_key = FALSE;
	unsigned char dgst[32];
	uint32_t val;
	buffer_t buf;

	if (data == end)
		return 0;

	keys = *data++;

	/* if we have a key, prefab the digest */
	if (stream->priv_key != NULL) {
		buffer_create_from_data(&buf, dgst, sizeof(dgst));
		if (!dcrypt_key_id_private(stream->priv_key, "sha256", &buf,
					   &error)) {
			io_stream_set_error(&stream->istream.iostream,
					    "Decryption error: "
					    "dcrypt_key_id_private failed: %s",
					    error);
			return -1;
		}
	} else if (stream->key_callback == NULL) {
		io_stream_set_error(&stream->istream.iostream,
				    "Decryption error: "
				    "no private key available");
		return -1;
	}

	/* for each key */
	for(;keys>0;keys--) {
		if ((size_t)(end-data) < 1 + (ssize_t)sizeof(dgst))
			return 0;
		ktype = *data++;

		if (stream->priv_key != NULL) {
			/* see if key matches to the one we have */
			if (memcmp(dgst, data, sizeof(dgst)) == 0) {
				have_key = TRUE;
				break;
			}
		} else if (stream->key_callback != NULL) {
			const char *hexdgst = /* digest length */
				binary_to_hex(data, sizeof(dgst));
			if (stream->priv_key != NULL)
				dcrypt_key_unref_private(&stream->priv_key);
			/* hope you going to give us right key.. */
			int ret = stream->key_callback(hexdgst,
				&stream->priv_key, &error, stream->key_context);
			if (ret < 0) {
				io_stream_set_error(&stream->istream.iostream,
						    "Private key not available: "
						    "%s", error);
				return -1;
			}
			if (ret > 0) {
				have_key = TRUE;
				break;
			}
		}
		data += sizeof(dgst);

		/* wasn't correct key, skip over some data */
		if (!get_msb32(&data, end, &val) ||
		    !get_msb32(&data, end, &val))
			return 0;
	}

	/* didn't find matching key */
	if (!have_key) {
		io_stream_set_error(&stream->istream.iostream,
				    "Decryption error: "
				    "no private key available");
		return -1;
	}

	data += sizeof(dgst);

	const unsigned char *ephemeral_key;
	uint32_t ep_key_len;
	const unsigned char *encrypted_key;
	uint32_t eklen;
	const unsigned char *ekhash;
	uint32_t ekhash_len;

	/* read ephemeral key (can be missing for RSA) */
	if (!get_msb32(&data, end, &ep_key_len) ||
	    (size_t)(end-data) < ep_key_len)
		return 0;
	ephemeral_key = data;
	data += ep_key_len;

	/* read encrypted key */
	if (!get_msb32(&data, end, &eklen) || (size_t)(end-data) < eklen)
		return 0;
	encrypted_key = data;
	data += eklen;

	/* read key data hash */
	if (!get_msb32(&data, end, &ekhash_len) ||
	    (size_t)(end-data) < ekhash_len)
		return 0;
	ekhash = data;
	data += ekhash_len;

	/* decrypt the seed */
	if (ktype == DCRYPT_KEY_RSA) {
		if (!dcrypt_rsa_decrypt(stream->priv_key, encrypted_key, eklen,
					key, DCRYPT_PADDING_RSA_PKCS1_OAEP,
					&error)) {
			io_stream_set_error(&stream->istream.iostream,
					    "key decryption error: %s", error);
			return -1;
		}
	} else if (ktype == DCRYPT_KEY_EC) {
		/* perform ECDHE */
		buffer_t *temp_key = t_buffer_create(256);
		buffer_t *secret = t_buffer_create(256);
		buffer_t peer_key;
		buffer_create_from_const_data(&peer_key,
			ephemeral_key, ep_key_len);
		if (!dcrypt_ecdh_derive_secret_local(stream->priv_key,
			&peer_key, secret, &error)) {
			io_stream_set_error(&stream->istream.iostream,
				"Key decryption error: corrupted header");
			return -1;
		}

		/* use shared secret and peer key to generate decryption key,
		   AES-256-CBC has 32 byte key and 16 byte IV */
		if (!dcrypt_pbkdf2(secret->data, secret->used,
				   peer_key.data, peer_key.used,
				   malg, rounds, temp_key, 32+16, &error)) {
			safe_memset(buffer_get_modifiable_data(secret, 0),
				    0, secret->used);
			io_stream_set_error(&stream->istream.iostream,
					    "Key decryption error: %s", error);
			return -1;
		}

		safe_memset(buffer_get_modifiable_data(secret, 0),
			    0, secret->used);
		if (temp_key->used != 32+16) {
			safe_memset(buffer_get_modifiable_data(temp_key, 0),
				    0, temp_key->used);
			io_stream_set_error(&stream->istream.iostream,
					    "Cannot perform key decryption: "
					    "invalid temporary key");
			return -1;
		}
		struct dcrypt_context_symmetric *dctx;
		if (!dcrypt_ctx_sym_create("AES-256-CBC", DCRYPT_MODE_DECRYPT,
					   &dctx, &error)) {
			safe_memset(buffer_get_modifiable_data(temp_key, 0),
				    0, temp_key->used);
			io_stream_set_error(&stream->istream.iostream,
					    "Key decryption error: %s", error);
			return -1;
		}
		const unsigned char *ptr = temp_key->data;

		/* we use ephemeral_key for IV */
		dcrypt_ctx_sym_set_key(dctx, ptr, 32);
		dcrypt_ctx_sym_set_iv(dctx, ptr+32, 16);
		safe_memset(buffer_get_modifiable_data(temp_key, 0),
			    0, temp_key->used);

		int ec = 0;
		if (!dcrypt_ctx_sym_init(dctx, &error) ||
		    !dcrypt_ctx_sym_update(dctx, encrypted_key, eklen,
					   key, &error) ||
		    !dcrypt_ctx_sym_final(dctx, key, &error)) {
			io_stream_set_error(&stream->istream.iostream,
					    "Cannot perform key decryption: %s",
					    error);
			ec = -1;
		}

		if (key->used != key_len) {
			io_stream_set_error(&stream->istream.iostream,
					    "Cannot perform key decryption: "
					    "invalid key length");
			ec = -1;
		}

		dcrypt_ctx_sym_destroy(&dctx);
		if (ec != 0) return ec;
	} else {
		io_stream_set_error(&stream->istream.iostream,
				    "Decryption error: "
				    "unsupported key type 0x%02x", ktype);
		return -1;
	}

	/* make sure we were able to decrypt the encrypted key correctly */
	const struct hash_method *hash = hash_method_lookup(t_str_lcase(malg));
	if (hash == NULL) {
		safe_memset(buffer_get_modifiable_data(key, 0), 0, key->used);
		io_stream_set_error(&stream->istream.iostream,
				    "Decryption error: "
				     "unsupported hash algorithm: %s", malg);
		return -1;
	}
	unsigned char hctx[hash->context_size];
	unsigned char hres[hash->digest_size];
	hash->init(hctx);
	hash->loop(hctx, key->data, key->used);
	hash->result(hctx, hres);

	for(int i = 1; i < 2049; i++) {
		uint32_t i_msb = cpu32_to_be(i);

		hash->init(hctx);
		hash->loop(hctx, hres, sizeof(hres));
		hash->loop(hctx, &i_msb, sizeof(i_msb));
		hash->result(hctx, hres);
	}

	/* do the comparison */
	if (memcmp(ekhash, hres, I_MIN(ekhash_len, sizeof(hres))) != 0) {
		safe_memset(buffer_get_modifiable_data(key, 0), 0, key->used);
		io_stream_set_error(&stream->istream.iostream,
				    "Decryption error: "
				    "corrupted header ekhash");
		return -1;
	}
	return 1;
}

static int
i_stream_decrypt_header_contents(struct decrypt_istream *stream,
				 const unsigned char *data, size_t size)
{
	const unsigned char *end = data + size;
	bool failed = FALSE;

	/* read cipher OID */
	const char *calg;
	if (!i_stream_decrypt_der(&data, end, &calg))
		return 0;
	if (calg == NULL ||
	    !dcrypt_ctx_sym_create(calg, DCRYPT_MODE_DECRYPT,
				   &stream->ctx_sym, NULL)) {
		io_stream_set_error(&stream->istream.iostream,
				    "Decryption error: "
				    "unsupported/invalid cipher: %s", calg);
		return -1;
	}

	/* read MAC oid (MAC is used for PBKDF2 and key data digest, too) */
	const char *malg;
	if (!i_stream_decrypt_der(&data, end, &malg))
		return 0;
	if (malg == NULL || !dcrypt_ctx_hmac_create(malg, &stream->ctx_mac, NULL)) {
		io_stream_set_error(&stream->istream.iostream,
				    "Decryption error: "
				    "unsupported/invalid MAC algorithm: %s",
				    malg);
		return -1;
	}

	/* read rounds (for PBKDF2) */
	uint32_t rounds;
	if (!get_msb32(&data, end, &rounds))
		return 0;
	/* read key data length */
	uint32_t kdlen;
	if (!get_msb32(&data, end, &kdlen))
		return 0;

	size_t tagsize;

	if ((stream->flags & IO_STREAM_ENC_INTEGRITY_HMAC) ==
		IO_STREAM_ENC_INTEGRITY_HMAC) {
		tagsize = IOSTREAM_TAG_SIZE;
	} else if ((stream->flags & IO_STREAM_ENC_INTEGRITY_AEAD) ==
		IO_STREAM_ENC_INTEGRITY_AEAD) {
		tagsize = IOSTREAM_TAG_SIZE;
	} else {
		tagsize = 0;
	}

	/* how much key data we should be getting */
	size_t kl = dcrypt_ctx_sym_get_key_length(stream->ctx_sym) +
		dcrypt_ctx_sym_get_iv_length(stream->ctx_sym) + tagsize;
	buffer_t *keydata = t_buffer_create(kl);

	/* try to decrypt the keydata with a private key */
	int ret;
	if ((ret = i_stream_decrypt_key(stream, malg, rounds, data,
					end, keydata, kl)) <= 0)
		return ret;

	/* oh, it worked! */
	const unsigned char *ptr = keydata->data;
	if (keydata->used != kl) {
		/* but returned wrong amount of data */
		io_stream_set_error(&stream->istream.iostream,
				    "Key decryption error: "
				    "Key data length mismatch");
		return -1;
	}

	/* prime contexts */
	dcrypt_ctx_sym_set_key(stream->ctx_sym, ptr,
			       dcrypt_ctx_sym_get_key_length(stream->ctx_sym));
	ptr += dcrypt_ctx_sym_get_key_length(stream->ctx_sym);
	dcrypt_ctx_sym_set_iv(stream->ctx_sym, ptr,
			      dcrypt_ctx_sym_get_iv_length(stream->ctx_sym));
	stream->iv = i_malloc(dcrypt_ctx_sym_get_iv_length(stream->ctx_sym));
	memcpy(stream->iv, ptr, dcrypt_ctx_sym_get_iv_length(stream->ctx_sym));
	ptr += dcrypt_ctx_sym_get_iv_length(stream->ctx_sym);

	/* based on the chosen MAC, initialize HMAC or AEAD */
	if ((stream->flags & IO_STREAM_ENC_INTEGRITY_HMAC) ==
		IO_STREAM_ENC_INTEGRITY_HMAC) {
		const char *error;
		dcrypt_ctx_hmac_set_key(stream->ctx_mac, ptr, tagsize);
		if (!dcrypt_ctx_hmac_init(stream->ctx_mac, &error)) {
			io_stream_set_error(&stream->istream.iostream,
					    "MAC error: %s", error);
			stream->istream.istream.stream_errno = EINVAL;
			failed = TRUE;
		}
		stream->ftr = dcrypt_ctx_hmac_get_digest_length(stream->ctx_mac);
		stream->use_mac = TRUE;
	} else if ((stream->flags & IO_STREAM_ENC_INTEGRITY_AEAD) ==
		IO_STREAM_ENC_INTEGRITY_AEAD) {
		dcrypt_ctx_sym_set_aad(stream->ctx_sym, ptr, tagsize);
		stream->ftr = tagsize;
		stream->use_mac = TRUE;
	} else {
		stream->use_mac = FALSE;
	}
	/* destroy private key data */
	safe_memset(buffer_get_modifiable_data(keydata, 0), 0, keydata->used);
	buffer_set_used_size(keydata, 0);
	return failed ? -1 : 1;
}

static ssize_t
i_stream_decrypt_read_header(struct decrypt_istream *stream,
			     const unsigned char *data, size_t mlen)
{
	const char *error;
	const unsigned char *end = data + mlen;

	/* check magic */
	if (mlen < sizeof(IOSTREAM_CRYPT_MAGIC))
		return 0;
	if (memcmp(data, IOSTREAM_CRYPT_MAGIC, sizeof(IOSTREAM_CRYPT_MAGIC)) != 0) {
		io_stream_set_error(&stream->istream.iostream,
				    "Stream is not encrypted (invalid magic)");
		stream->istream.istream.stream_errno = EINVAL;
		return -1;
	}
	data += sizeof(IOSTREAM_CRYPT_MAGIC);

	if (data >= end)
		return 0; /* read more? */

	/* check version */
	if (*data == '\x01') {
		stream->format = DECRYPT_FORMAT_V1;
		return i_stream_decrypt_read_header_v1(stream, data+1,
						       end - (data+1));
	} else if (*data != '\x02') {
		io_stream_set_error(&stream->istream.iostream,
				    "Unsupported encrypted data 0x%02x", *data);
		return -1;
	}

	stream->format = DECRYPT_FORMAT_V2;

	data++;

	/* read flags */
	uint32_t flags;
	if (!get_msb32(&data, end, &flags))
		return 0;
	stream->flags = flags;

	/* get the total length of header */
	uint32_t hdr_len;
	if (!get_msb32(&data, end, &hdr_len))
		return 0;
	/* do not forget stream format */
	if ((size_t)(end-data)+1 < hdr_len)
		return 0;

	int ret;
	if ((ret = i_stream_decrypt_header_contents(stream, data, hdr_len)) < 0)
		return -1;
	else if (ret == 0) {
		io_stream_set_error(&stream->istream.iostream,
				    "Decryption error: truncate header length");
		stream->istream.istream.stream_errno = EPIPE;
		return -1;
	}
	stream->initialized = TRUE;

	/* if it all went well, try to initialize decryption context */
	if (!dcrypt_ctx_sym_init(stream->ctx_sym, &error)) {
		io_stream_set_error(&stream->istream.iostream,
				    "Decryption init error: %s", error);
		return -1;
	}
	return hdr_len;
}

static ssize_t
i_stream_decrypt_read(struct istream_private *stream)
{
	struct decrypt_istream *dstream =
		(struct decrypt_istream *)stream;
	const unsigned char *data;
	size_t size, decrypt_size;
	const char *error = NULL;
	int ret;
	bool check_mac = FALSE;

	/* not if it's broken */
	if (stream->istream.stream_errno != 0)
		return -1;

	for (;;) {
		/* remove skipped data from buffer */
		if (stream->skip > 0) {
			i_assert(stream->skip <= dstream->buf->used);
			buffer_delete(dstream->buf, 0, stream->skip);
			stream->pos -= stream->skip;
			stream->skip = 0;
		}

		stream->buffer = dstream->buf->data;

		i_assert(stream->pos <= dstream->buf->used);
		if (stream->pos >= dstream->istream.max_buffer_size) {
			/* stream buffer still at maximum */
			return -2;
		}

		/* if something is already decrypted, return as much of it as
		   we can */
		if (dstream->initialized && dstream->buf->used > 0) {
			size_t new_pos, bytes;

			/* only return up to max_buffer_size bytes, even when
			   buffer actually has more, as not to confuse the
			   caller */
			if (dstream->buf->used <=
				dstream->istream.max_buffer_size) {
				new_pos = dstream->buf->used;
				if (dstream->finalized)
					stream->istream.eof = TRUE;
			} else {
				new_pos = dstream->istream.max_buffer_size;
			}

			bytes = new_pos - stream->pos;
			stream->pos = new_pos;
			if (bytes > 0)
				return (ssize_t)bytes;
		}
		if (dstream->finalized) {
			/* all data decrypted */
			stream->istream.eof = TRUE;
			return -1;
		}

		/* need to read more input */
		ret = i_stream_read_memarea(stream->parent);
		if (ret == 0)
			return ret;

		data = i_stream_get_data(stream->parent, &size);

		if (ret == -1 &&
		    (size == 0 || stream->parent->stream_errno != 0)) {
			stream->istream.stream_errno =
				stream->parent->stream_errno;

			/* file was empty */
			if (!dstream->initialized &&
			    size == 0 && stream->parent->eof) {
				stream->istream.eof = TRUE;
				return -1;
			}

			if (stream->istream.stream_errno != 0)
				return -1;

			if (!dstream->initialized) {
				io_stream_set_error(&stream->iostream,
					"Decryption error: %s",
					"Input truncated in decryption header");
				stream->istream.stream_errno = EPIPE;
				return -1;
			}

			/* final block */
			if (dcrypt_ctx_sym_final(dstream->ctx_sym,
				dstream->buf, &error)) {
				dstream->finalized = TRUE;
				continue;
			}
			io_stream_set_error(&stream->iostream,
				"MAC error: %s", error);
			stream->istream.stream_errno = EINVAL;
			return -1;
		}

		if (!dstream->initialized) {
			ssize_t hret;

			if ((hret=i_stream_decrypt_read_header(
				dstream, data, size)) <= 0) {
				if (hret < 0) {
					if (stream->istream.stream_errno == 0)
						/* assume temporary failure */
						stream->istream.stream_errno = EIO;
					return -1;
				}

				if (hret == 0 && stream->parent->eof) {
					/* not encrypted by us */
					stream->istream.stream_errno = EPIPE;
					io_stream_set_error(&stream->iostream,
						"Truncated header");
					return -1;
				}
			}

			if (hret == 0) {
				/* see if we can get more data */
				if (ret == -2) {
					stream->istream.stream_errno = EINVAL;
					io_stream_set_error(&stream->iostream,
						"Header too large "
						"(more than %zu bytes)",
						size);
					return -1;
				}
				continue;
			} else {
				/* clean up buffer */
				safe_memset(buffer_get_modifiable_data(dstream->buf, 0),
					    0, dstream->buf->used);
				buffer_set_used_size(dstream->buf, 0);
				i_stream_skip(stream->parent, hret);
			}

			data = i_stream_get_data(stream->parent, &size);
		}
		decrypt_size = size;

		if (dstream->use_mac) {
			if (stream->parent->eof) {
				if (decrypt_size < dstream->ftr) {
					io_stream_set_error(&stream->iostream,
						"Decryption error: "
						"footer is longer than data");
					stream->istream.stream_errno = EINVAL;
					return -1;
				}
				check_mac = TRUE;
			} else {
				/* ignore footer's length of data until we
				   reach EOF */
				size -= dstream->ftr;
			}
			decrypt_size -= dstream->ftr;
			if ((dstream->flags & IO_STREAM_ENC_INTEGRITY_HMAC) ==
				IO_STREAM_ENC_INTEGRITY_HMAC) {
				if (!dcrypt_ctx_hmac_update(dstream->ctx_mac,
				    data, decrypt_size, &error)) {
					io_stream_set_error(&stream->iostream,
						"MAC error: %s", error);
					stream->istream.stream_errno = EINVAL;
					return -1;
				}
			}
		}

		if (check_mac) {
			if ((dstream->flags & IO_STREAM_ENC_INTEGRITY_HMAC) ==
				IO_STREAM_ENC_INTEGRITY_HMAC) {
				unsigned char dgst[dcrypt_ctx_hmac_get_digest_length(dstream->ctx_mac)];
				buffer_t db;
				buffer_create_from_data(&db, dgst, sizeof(dgst));
				if (!dcrypt_ctx_hmac_final(dstream->ctx_mac, &db, &error)) {
					io_stream_set_error(&stream->iostream,
						"Cannot verify MAC: %s", error);
					stream->istream.stream_errno = EINVAL;
					return -1;
				}
				if (memcmp(dgst, data + decrypt_size,
					dcrypt_ctx_hmac_get_digest_length(dstream->ctx_mac)) != 0) {
					io_stream_set_error(&stream->iostream,
						"Cannot verify MAC: mismatch");
					stream->istream.stream_errno = EINVAL;
					return -1;
				}
			} else if ((dstream->flags & IO_STREAM_ENC_INTEGRITY_AEAD) ==
				IO_STREAM_ENC_INTEGRITY_AEAD) {
				dcrypt_ctx_sym_set_tag(dstream->ctx_sym,
						       data + decrypt_size,
						       dstream->ftr);
			}
		}

		if (!dcrypt_ctx_sym_update(dstream->ctx_sym,
		    data, decrypt_size, dstream->buf, &error)) {
			io_stream_set_error(&stream->iostream,
				"Decryption error: %s", error);
			stream->istream.stream_errno = EINVAL;
			return -1;
		}
		i_stream_skip(stream->parent, size);
	}
}

static void
i_stream_decrypt_seek(struct istream_private *stream, uoff_t v_offset,
		      bool mark ATTR_UNUSED)
{
	struct decrypt_istream *dstream =
		(struct decrypt_istream *)stream;

	if (i_stream_nonseekable_try_seek(stream, v_offset))
		return;

	/* have to seek backwards - reset crypt state and retry */
	i_stream_decrypt_reset(dstream);
	if (!i_stream_nonseekable_try_seek(stream, v_offset))
		i_unreached();
}

static void i_stream_decrypt_close(struct iostream_private *stream,
				   bool close_parent)
{
	struct decrypt_istream *dstream =
		(struct decrypt_istream *)stream;

	if (close_parent)
		i_stream_close(dstream->istream.parent);
}

static void i_stream_decrypt_destroy(struct iostream_private *stream)
{
	struct decrypt_istream *dstream =
		(struct decrypt_istream *)stream;

	buffer_free(&dstream->buf);
	if (dstream->iv != NULL)
		i_free_and_null(dstream->iv);
	if (dstream->ctx_sym != NULL)
		dcrypt_ctx_sym_destroy(&dstream->ctx_sym);
	if (dstream->ctx_mac != NULL)
		dcrypt_ctx_hmac_destroy(&dstream->ctx_mac);
	if (dstream->priv_key != NULL)
		dcrypt_key_unref_private(&dstream->priv_key);

	i_stream_unref(&dstream->istream.parent);
}

static struct decrypt_istream *
i_stream_create_decrypt_common(struct istream *input)
{
	struct decrypt_istream *dstream;

	dstream = i_new(struct decrypt_istream, 1);
	dstream->istream.max_buffer_size = input->real_stream->max_buffer_size;
	dstream->istream.read = i_stream_decrypt_read;
	if (input->seekable)
		dstream->istream.seek = i_stream_decrypt_seek;
	dstream->istream.iostream.close = i_stream_decrypt_close;
	dstream->istream.iostream.destroy = i_stream_decrypt_destroy;

	dstream->istream.istream.readable_fd = FALSE;
	dstream->istream.istream.blocking = input->blocking;
	dstream->istream.istream.seekable = input->seekable;

	dstream->buf = buffer_create_dynamic(default_pool, 512);

	(void)i_stream_create(&dstream->istream, input,
			      i_stream_get_fd(input), 0);
	return dstream;
}

struct istream *
i_stream_create_decrypt(struct istream *input,
			struct dcrypt_private_key *priv_key)
{
	struct decrypt_istream *dstream;

	dstream = i_stream_create_decrypt_common(input);
	dcrypt_key_ref_private(priv_key);
	dstream->priv_key = priv_key;
	return &dstream->istream.istream;
}

struct istream *
i_stream_create_sym_decrypt(struct istream *input,
			    struct dcrypt_context_symmetric *ctx)
{
	const char *error;
	int ec;
	struct decrypt_istream *dstream;
	dstream = i_stream_create_decrypt_common(input);
	dstream->use_mac = FALSE;
	dstream->initialized = TRUE;
	dstream->symmetric = TRUE;

	if (!dcrypt_ctx_sym_init(ctx, &error)) ec = -1;
	else ec = 0;

	dstream->ctx_sym = ctx;

	if (ec != 0) {
		io_stream_set_error(&dstream->istream.iostream,
				    "Cannot initialize decryption: %s", error);
		dstream->istream.istream.stream_errno = EIO;
	};

	return &dstream->istream.istream;
}

struct istream *
i_stream_create_decrypt_callback(struct istream *input,
				 i_stream_decrypt_get_key_callback_t *callback,
				 void *context)
{
	struct decrypt_istream *dstream;

	i_assert(callback != NULL);

	dstream = i_stream_create_decrypt_common(input);
	dstream->key_callback = callback;
	dstream->key_context = context;
	return &dstream->istream.istream;
}
