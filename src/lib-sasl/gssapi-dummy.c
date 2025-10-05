/* Copyright (c) 2023 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "buffer.h"
#include "auth-gssapi.h"
#include "gssapi-dummy.h"

#define GSS_KRB5_DUMMY_FAIL_CODE 1

struct gss_name_struct {
	char *name;
};

struct gss_cred_id_struct {
	pool_t pool;
	const char *desired_name;
};

struct gss_ctx_id_struct {
	pool_t pool;

	const char *src_name;
	const char *dst_name;
	OM_uint32 req_flags;

	gss_OID_desc mech_type;
};

gss_OID GSS_C_NT_HOSTBASED_SERVICE = NULL;
const gss_OID GSS_KRB5_NT_PRINCIPAL_NAME = NULL;

static void gss_alloc_buffer(gss_buffer_t buffer, size_t length);

char *client_principal = NULL;
char *server_principal = NULL;

void gss_dummy_kinit(const char *principal)
{
	i_free(client_principal);
	client_principal = i_strdup(principal);
}

void gss_dummy_add_principal(const char *principal)
{
	i_free(server_principal);
	server_principal = i_strdup(principal);
}

void gss_dummy_deinit(void)
{
	i_free(client_principal);
	i_free(server_principal);
}

OM_uint32 KRB5_CALLCONV
gss_acquire_cred(OM_uint32 *minor_status, gss_name_t desired_name,
		 OM_uint32 time_req, gss_OID_set desired_mechs,
		 gss_cred_usage_t cred_usage, gss_cred_id_t *output_cred_handle,
		 gss_OID_set *actual_mechs, OM_uint32 *time_rec)
{
	pool_t pool;
	gss_cred_id_t cred_handle;

	i_assert(time_req == 0); // Not implemented
	i_assert(desired_mechs == GSS_C_NULL_OID_SET); // Not implemented
	i_assert(actual_mechs == NULL); // Not implemented
	i_assert(time_rec == NULL); // Not implemented
	i_assert(cred_usage == GSS_C_ACCEPT); // Not implemented

	pool = pool_alloconly_create(MEMPOOL_GROWING"gss_cred_id", 256);
	cred_handle = p_new(pool, struct gss_cred_id_struct, 1);
	cred_handle->pool = pool;
	cred_handle->desired_name = p_strdup(pool, desired_name->name);

	*output_cred_handle = cred_handle;
	*minor_status = 0;
	return 0;
}

OM_uint32 KRB5_CALLCONV
gss_release_cred(OM_uint32 *minor_status, gss_cred_id_t *cred_handle)
{
	pool_unref(&(*cred_handle)->pool);
	*cred_handle = NULL;

	*minor_status = 0;
	return 0;
}

static void _encode_uint32(buffer_t *output, OM_uint32 num)
{
	buffer_append_c(output, (uint8_t)(num >> 24));
	buffer_append_c(output, (uint8_t)(num >> 16));
	buffer_append_c(output, (uint8_t)(num >> 8));
	buffer_append_c(output, (uint8_t)(num >> 0));
}

static void _encode_buffer(buffer_t *output, gss_buffer_t buf)
{
	_encode_uint32(output, buf->length);
	buffer_append(output, buf->value, buf->length);
}

OM_uint32 KRB5_CALLCONV
gss_init_sec_context(OM_uint32 *minor_status,
		     gss_cred_id_t claimant_cred_handle,
		     gss_ctx_id_t *context_handle, gss_name_t target_name,
		     gss_OID mech_type, OM_uint32 req_flags,
		     OM_uint32 time_req,
		     gss_channel_bindings_t input_chan_bindings,
		     gss_buffer_t input_token ATTR_UNUSED,
		     gss_OID *actual_mech_type,
		     gss_buffer_t output_token, OM_uint32 *ret_flags,
		     OM_uint32 *time_rec)
{
	pool_t pool;
	struct gss_ctx_id_struct *ctx;

	i_assert(claimant_cred_handle == GSS_C_NO_CREDENTIAL); // Not implemented
	i_assert(time_req == 0); // Not implemented
	i_assert(time_req == 0); // Not implemented
	i_assert(ret_flags == NULL); // Not implemented
	i_assert(time_rec == NULL); // Not implemented

	pool = pool_alloconly_create(MEMPOOL_GROWING"gss_ctx_id", 256);
	ctx = p_new(pool, struct gss_ctx_id_struct, 1);
	ctx->pool = pool;
	ctx->src_name = p_strdup(pool, client_principal);
	ctx->dst_name = p_strdup(pool, target_name->name);
	ctx->req_flags = req_flags;
	ctx->mech_type = *mech_type;

	size_t src_name_len = strlen(ctx->src_name);
	size_t cbind_len = 0;
	if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) {
		cbind_len = 4 + 4 +
			input_chan_bindings->initiator_address.length +
			input_chan_bindings->acceptor_address.length +
			input_chan_bindings->application_data.length;
	}
	buffer_t *output = t_buffer_create(
		4 + ctx->mech_type.length + 4 + src_name_len + cbind_len);
	_encode_uint32(output, ctx->mech_type.length);
	buffer_append(output, ctx->mech_type.elements, ctx->mech_type.length);
	_encode_uint32(output, src_name_len);
	buffer_append(output, ctx->src_name, src_name_len);
	if (input_chan_bindings != GSS_C_NO_CHANNEL_BINDINGS) {
		_encode_uint32(output, input_chan_bindings->initiator_addrtype);
		_encode_uint32(output, input_chan_bindings->acceptor_addrtype);
		_encode_buffer(output, &input_chan_bindings->initiator_address);
		_encode_buffer(output, &input_chan_bindings->acceptor_address);
		_encode_buffer(output, &input_chan_bindings->application_data);
	}

	gss_alloc_buffer(output_token, output->used);
	memcpy(output_token->value, output->data, output->used);

	*context_handle = ctx;
	if (actual_mech_type != NULL)
		*actual_mech_type = &ctx->mech_type;

	*minor_status = 0;
	return 0;
}

static int
_decode_uint32(const unsigned char **_input, size_t *_input_left,
	       OM_uint32 *num_r)
{
	const unsigned char *input = *_input;
	size_t input_left = *_input_left;

	if (input_left < 4)
		return -1;

	*num_r = (OM_uint32)(input[0] << 24) | (OM_uint32)(input[1] << 16) |
		 (OM_uint32)(input[2] << 8) | (OM_uint32)(input[3] << 0);

	*_input += 4;
	*_input_left -= 4;
	return 0;
}

static int
_decode_buffer(const unsigned char **_input, size_t *_input_left,
	       gss_buffer_t out)
{
	OM_uint32 len;

	if (_decode_uint32(_input, _input_left, &len) < 0)
		return -1;
	i_zero(out);
	if (len > 0) {
		out->value = t_memdup_noconst(*_input, len);
		out->length = len;
		*_input += len;
		*_input_left -= len;
	}
	return 0;
}

static bool
_gss_buffer_cmp(gss_buffer_t buf1, gss_buffer_t buf2)
{
	if (buf1->length == 0 || buf2->length == 0)
		return (buf1->length == buf2->length);
	return (memcmp(buf1->value, buf2->value,
		       I_MIN(buf1->length, buf2->length)) == 0);
}

static OM_uint32
gss_parse_sec_context(struct gss_ctx_id_struct *ctx,
		      gss_buffer_t input_token_buffer,
		      gss_channel_bindings_t input_chan_bindings)
{
	const unsigned char *input = input_token_buffer->value;
	size_t input_left = input_token_buffer->length;

	if (_decode_uint32(&input, &input_left, &ctx->mech_type.length) < 0)
	    return GSS_S_BAD_MECH;
	if (ctx->mech_type.length > input_left)
	    return GSS_S_BAD_MECH;
	ctx->mech_type.elements = p_malloc(ctx->pool, ctx->mech_type.length);
	memcpy(ctx->mech_type.elements, input, ctx->mech_type.length);
	input += ctx->mech_type.length;
	input_left -= ctx->mech_type.length;

	OM_uint32 src_name_len;
	if (_decode_uint32(&input, &input_left, &src_name_len) < 0)
	    return GSS_S_BAD_MECH;
	if (input_left < src_name_len)
	    return GSS_S_BAD_NAME;
	ctx->src_name = p_strndup(ctx->pool, (const char *)input, src_name_len);
	input += src_name_len;
	input_left -= src_name_len;

	if (input_chan_bindings == GSS_C_NO_CHANNEL_BINDINGS) {
		if (input_left != 0)
			return GSS_S_BAD_MECH;
	} else {
		OM_uint32 initiator_addrtype;
		OM_uint32 acceptor_addrtype;
		gss_buffer_desc initiator_address;
		gss_buffer_desc acceptor_address;
		gss_buffer_desc application_data;

		if (_decode_uint32(&input, &input_left,
				   &initiator_addrtype) < 0)
			return GSS_S_BAD_MECH;
		if (_decode_uint32(&input, &input_left,
				   &acceptor_addrtype) < 0)
			return GSS_S_BAD_MECH;

		if (_decode_buffer(&input, &input_left, &initiator_address) < 0)
			return GSS_S_BAD_MECH;
		if (_decode_buffer(&input, &input_left, &acceptor_address) < 0)
			return GSS_S_BAD_MECH;
		if (_decode_buffer(&input, &input_left, &application_data) < 0)
			return GSS_S_BAD_MECH;

		if (initiator_addrtype !=
		    input_chan_bindings->initiator_addrtype)
			return GSS_S_BAD_BINDINGS;
		if (acceptor_addrtype !=
		    input_chan_bindings->acceptor_addrtype)
			return GSS_S_BAD_BINDINGS;
		if (!_gss_buffer_cmp(&initiator_address,
				     &input_chan_bindings->initiator_address))
			return GSS_S_BAD_BINDINGS;
		if (!_gss_buffer_cmp(&acceptor_address,
				     &input_chan_bindings->acceptor_address))
			return GSS_S_BAD_BINDINGS;
		if (!_gss_buffer_cmp(&application_data,
				     &input_chan_bindings->application_data))
			return GSS_S_BAD_BINDINGS;
	}
	return 0;
}

OM_uint32 KRB5_CALLCONV
gss_accept_sec_context(OM_uint32 *minor_status, gss_ctx_id_t *context_handle,
		       gss_cred_id_t acceptor_cred_handle,
		       gss_buffer_t input_token_buffer,
		       gss_channel_bindings_t input_chan_bindings,
		       gss_name_t *src_name, gss_OID *mech_type,
		       gss_buffer_t output_token, OM_uint32 *ret_flags,
		       OM_uint32 *time_rec,
		       gss_cred_id_t *delegated_cred_handle)
{
	pool_t pool;
	struct gss_ctx_id_struct *ctx;
	OM_uint32 major_status;

	*minor_status = 0;

	i_assert(ret_flags == NULL);
	i_assert(time_rec == NULL);
	i_assert(delegated_cred_handle == NULL);

	pool = pool_alloconly_create(MEMPOOL_GROWING"gss_ctx_id", 256);
	ctx = p_new(pool, struct gss_ctx_id_struct, 1);
	ctx->pool = pool;
	ctx->dst_name = p_strdup(pool, acceptor_cred_handle->desired_name);

	major_status = gss_parse_sec_context(ctx, input_token_buffer,
					     input_chan_bindings);
	if (major_status != 0) {
		pool_unref(&pool);
		return major_status;
	}

	if (server_principal == NULL ||
	    strcmp(ctx->src_name, server_principal) != 0) {
		pool_unref(&pool);
		*minor_status = GSS_KRB5_DUMMY_FAIL_CODE;
		return GSS_S_NO_CRED;
	}

	struct gss_name_struct *name = i_new(struct gss_name_struct, 1);
	name->name = i_strdup(ctx->src_name);

	*context_handle = ctx;
	*src_name = name;
	*mech_type = &ctx->mech_type;
	gss_alloc_buffer(output_token, 0);

	return 0;
}

OM_uint32 KRB5_CALLCONV
gss_delete_sec_context(OM_uint32 *minor_status, gss_ctx_id_t *context_handle,
		       gss_buffer_t output_token)
{
	struct gss_ctx_id_struct *ctx = *context_handle;

	i_assert(output_token == GSS_C_NO_BUFFER);

	pool_unref(&ctx->pool);
	*context_handle = NULL;

	*minor_status = 0;
	return 0;
}

OM_uint32 KRB5_CALLCONV
gss_wrap(OM_uint32 * minor_status, gss_ctx_id_t context_handle ATTR_UNUSED,
	 int conf_req_flag, gss_qop_t qop_req,
	 gss_buffer_t input_message_buffer, int *conf_state,
	 gss_buffer_t output_message_buffer)
{
	i_assert(conf_req_flag == 0);
	i_assert(qop_req == GSS_C_QOP_DEFAULT);
	i_assert(conf_state == NULL);

	gss_alloc_buffer(output_message_buffer, input_message_buffer->length);
	memcpy(output_message_buffer->value, input_message_buffer->value,
	       input_message_buffer->length);

	*minor_status = 0;
	return 0;
}

OM_uint32 KRB5_CALLCONV
gss_unwrap(OM_uint32 *minor_status, gss_ctx_id_t context_handle ATTR_UNUSED,
	   gss_buffer_t input_message_buffer,
	   gss_buffer_t output_message_buffer, int *conf_state,
	   gss_qop_t *qop_state ATTR_UNUSED)
{
	i_assert(conf_state == NULL);

	gss_alloc_buffer(output_message_buffer, input_message_buffer->length);
	memcpy(output_message_buffer->value, input_message_buffer->value,
	       input_message_buffer->length);

	*minor_status = 0;
	return 0;
}

OM_uint32 KRB5_CALLCONV
gss_display_status(OM_uint32 *minor_status,
		   OM_uint32 status_value,
		   int status_type, gss_OID mech_type ATTR_UNUSED,
		   OM_uint32 *message_context ATTR_UNUSED,
		   gss_buffer_t status_string)
{
	char *error_msg = NULL;

	*minor_status = 0;

	switch (status_type) {
	case  GSS_C_GSS_CODE:
		switch (status_value) {
		case GSS_S_NO_CRED:
			error_msg = i_strdup("No valid credentials.");
			break;
		default:
			break;
		}
		break;
	case GSS_C_MECH_CODE:
		switch (status_value) {
		case GSS_KRB5_DUMMY_FAIL_CODE:
			error_msg = i_strdup("Kerberos5 dummy says no.");
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	if (error_msg == NULL) {
		error_msg = i_strdup_printf("STATUS: %"PRIu32":%"PRIu32,
					    status_type, status_value);
	}

	status_string->value = error_msg;
	status_string->length = strlen(error_msg);

	return 0;
}

OM_uint32 KRB5_CALLCONV
gss_compare_name(OM_uint32 *minor_status, gss_name_t name1, gss_name_t name2,
		 int *name_equal)
{
	*name_equal = (strcmp(name1->name, name2->name) == 0 ? 1 : 0);

	*minor_status = 0;
	return 0;
}

OM_uint32 KRB5_CALLCONV
gss_display_name(OM_uint32 *minor_status, gss_name_t input_name,
		 gss_buffer_t output_name_buffer, gss_OID *output_name_type)
{
	size_t input_name_len = strlen(input_name->name);

	gss_alloc_buffer(output_name_buffer, input_name_len);
	memcpy(output_name_buffer->value, input_name->name, input_name_len);
	output_name_buffer->length = input_name_len;

	if (output_name_type != NULL)
		*output_name_type = GSS_KRB5_NT_PRINCIPAL_NAME;

	*minor_status = 0;
	return 0;
}

OM_uint32 KRB5_CALLCONV
gss_import_name(OM_uint32 *minor_status, gss_buffer_t input_name_buffer,
		gss_OID input_name_type ATTR_UNUSED, gss_name_t *output_name)
{
	struct gss_name_struct *name;

	name = i_new(struct gss_name_struct, 1);
	name->name = i_strndup(input_name_buffer->value,
			       input_name_buffer->length);
	*output_name = name;

	*minor_status = 0;
	return GSS_S_COMPLETE;
}

OM_uint32 KRB5_CALLCONV
gss_release_name(OM_uint32 *minor_status, gss_name_t *input_name)
{
	if (*input_name == NULL) {
		*minor_status = 0;
		return GSS_S_COMPLETE;
	}

	i_free((*input_name)->name);
	i_free((*input_name));

	*minor_status = 0;
	return GSS_S_COMPLETE;
}

static void gss_alloc_buffer(gss_buffer_t buffer, size_t length)
{
	i_zero(buffer);
	buffer->length = length;
	if (length > 0)
		buffer->value = i_malloc(length);
}

OM_uint32 KRB5_CALLCONV
gss_release_buffer(OM_uint32 *minor_status, gss_buffer_t buffer)
{
	if (buffer != NULL) {
		if (buffer->value != NULL)
			i_free(buffer->value);
		i_zero(buffer);
	}

	*minor_status = 0;
	return GSS_S_COMPLETE;
}

OM_uint32 KRB5_CALLCONV
gss_duplicate_name(OM_uint32  *minor_status, const gss_name_t input_name,
		   gss_name_t * dest_name)
{
	struct gss_name_struct *name;

	name = i_new(struct gss_name_struct, 1);
	name->name = i_strdup(input_name->name);
	*dest_name = name;

	*minor_status = 0;
	return GSS_S_COMPLETE;
}
