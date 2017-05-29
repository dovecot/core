#ifndef ISTREAM_QP_H
#define ISTREAM_QP_H

#include "qp-encoder.h"

#define ISTREAM_QP_ENCODER_MAX_LINE_LENGTH 75

struct istream *i_stream_create_qp_decoder(struct istream *input);
struct istream *i_stream_create_qp_encoder(struct istream *input,
					   enum qp_encoder_flag flags);

#endif
