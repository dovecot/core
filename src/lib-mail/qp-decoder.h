#ifndef QP_DECODER_H
#define QP_DECODER_H

/* Initialize quoted-printable decoder. Write all the decoded output to dest. */
struct qp_decoder *qp_decoder_init(buffer_t *dest);
void qp_decoder_deinit(struct qp_decoder **qp);

/* Translate more quoted printable data into binary. Returns 0 if input was
   valid, -1 if there were some decoding errors (which were skipped over).
   LFs without preceding CR are returned as CRLF (but =0A isn't). */
int qp_decoder_more(struct qp_decoder *qp, const unsigned char *src,
		    size_t src_size, size_t *invalid_src_pos_r,
		    const char **error_r);
/* Finish decoding any pending input. Returns the same as qp_decoder_more().
   This function also resets the entire decoder state, so the same decoder can
   be used to decode more data if wanted. */
int qp_decoder_finish(struct qp_decoder *qp, const char **error_r);

#endif
