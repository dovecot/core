/* Copyright (c) 2009-2013 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "iostream-openssl.h"

/* 2 or 5. Haven't seen their difference explained anywhere, but 2 is the
   default.. */
#define DH_GENERATOR 2

static int dh_param_bitsizes[] = { 512, 1024 };

static int
generate_dh_parameters(int bitsize, buffer_t *output, const char **error_r)
{
        DH *dh;
	unsigned char *p;
	int len, len2;

	dh = DH_generate_parameters(bitsize, DH_GENERATOR, NULL, NULL);
	if (dh == NULL) {
		*error_r = t_strdup_printf(
			"DH_generate_parameters(bits=%d, gen=%d) failed: %s",
			bitsize, DH_GENERATOR, openssl_iostream_error());
		return -1;
	}

	len = i2d_DHparams(dh, NULL);
	if (len < 0) {
		*error_r = t_strdup_printf("i2d_DHparams() failed: %s",
					   openssl_iostream_error());
		DH_free(dh);
		return -1;
	}

	buffer_append(output, &bitsize, sizeof(bitsize));
	buffer_append(output, &len, sizeof(len));

	p = buffer_append_space_unsafe(output, len);
	len2 = i2d_DHparams(dh, &p);
	i_assert(len == len2);
	DH_free(dh);
	return 0;
}

int openssl_iostream_generate_params(buffer_t *output, const char **error_r)
{
	unsigned int i;

	for (i = 0; i < N_ELEMENTS(dh_param_bitsizes); i++) {
		if (generate_dh_parameters(dh_param_bitsizes[i],
					   output, error_r) < 0)
			return -1;
	}
	buffer_append_zero(output, sizeof(int));
	return 0;
}

static int read_int(const unsigned char **data, const unsigned char *end)
{
	unsigned int len = end - *data;
	int ret;

	if (len < sizeof(ret))
		return -1;
	memcpy(&ret, *data, sizeof(ret));
	*data += sizeof(ret);
	return ret;
}

static int
read_dh_parameters_next(struct ssl_iostream_context *ctx,
			const unsigned char **data, const unsigned char *end)
{
	const unsigned char *dbuf;
	DH *dh;
	int bits, len, ret = 1;

	/* get bit size. 0 ends the DH parameters list. */
	if ((bits = read_int(data, end)) <= 0)
		return bits;

	/* get data size */
	if ((len = read_int(data, end)) <= 0 || end - *data < len)
		return -1;

	dbuf = *data;
	dh = d2i_DHparams(NULL, &dbuf, len);
	*data += len;

	if (dh == NULL)
		return -1;

	switch (bits) {
	case 512:
		ctx->dh_512 = dh;
		break;
	case 1024:
		ctx->dh_1024 = dh;
		break;
	default:
		ret = -1;
		break;
	}
	return ret;
}

int openssl_iostream_context_import_params(struct ssl_iostream_context *ctx,
					   const buffer_t *input)
{
	const unsigned char *data, *end;
	int ret;

	openssl_iostream_context_free_params(ctx);

	data = input->data;
	end = data + input->used;
	while ((ret = read_dh_parameters_next(ctx, &data, end)) > 0) ;

	return ret < 0 || data != end ? -1 : 0;
}

void openssl_iostream_context_free_params(struct ssl_iostream_context *ctx)
{
	if (ctx->dh_512 != NULL) {
		DH_free(ctx->dh_512);
                ctx->dh_512 = NULL;
	}
	if (ctx->dh_1024 != NULL) {
		DH_free(ctx->dh_1024);
                ctx->dh_1024 = NULL;
	}
}
