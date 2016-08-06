#ifndef DCRYPT_IOSTREAM_H
#define DCRYPT_IOSTREAM_H 1

static const unsigned char IOSTREAM_CRYPT_MAGIC[] = {'C','R','Y','P','T','E','D','\x03','\x07'};
#define IOSTREAM_CRYPT_VERSION 2
#define IOSTREAM_TAG_SIZE 16

enum io_stream_encrypt_flags {
	IO_STREAM_ENC_INTEGRITY_HMAC = 0x1,
	IO_STREAM_ENC_INTEGRITY_AEAD = 0x2,
	IO_STREAM_ENC_INTEGRITY_NONE = 0x4,
	IO_STREAM_ENC_VERSION_1      = 0x8,
};

#endif
