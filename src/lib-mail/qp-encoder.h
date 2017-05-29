#ifndef QP_ENCODER_H
#define QP_ENCODER_H 1

enum qp_encoder_flag {
	/* encode spaces as underscores, encode crlfs, adds =?utf-8?q?..?= encapsulation */
	QP_ENCODER_FLAG_HEADER_FORMAT = 0x1,
	/* treat input as true binary, no lf => crlf conversion, only CRLF is preserved */
	QP_ENCODER_FLAG_BINARY_DATA   = 0x2,
};

/* Initialize quoted-printable encoder. Write all the encoded output to dest. */
struct qp_encoder *qp_encoder_init(string_t *dest, unsigned int max_length,
				   enum qp_encoder_flag flags);
void qp_encoder_deinit(struct qp_encoder **qp);

/* Translate more (binary) data into quoted printable.
   If QP_ENCODER_FLAG_BINARY_DATA is not set, text is assumed to be in
   UTF-8 (but not enforced). No other character sets are supported. */
void qp_encoder_more(struct qp_encoder *qp, const void *src, size_t src_size);
/* Finish encoding any pending input.
   This function also resets the entire encoder state, so the same encoder can
   be used to encode more data if wanted. */
void qp_encoder_finish(struct qp_encoder *qp);

#endif
