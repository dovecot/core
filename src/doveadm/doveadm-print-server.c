/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "client-connection.h"
#include "doveadm-server.h"
#include "doveadm-print-private.h"

struct doveadm_print_server_context {
	unsigned int header_idx, header_count;

	string_t *str;
};

static struct doveadm_print_server_context ctx;

static void doveadm_print_server_flush(void);

static void doveadm_print_server_init(void)
{
	ctx.str = str_new(default_pool, 256);
}

static void doveadm_print_server_deinit(void)
{
	str_free(&ctx.str);
}

static void
doveadm_print_server_header(const struct doveadm_print_header *hdr ATTR_UNUSED)
{
	/* no need to transfer these. the client should already know what
	   it's getting */
	ctx.header_count++;
}

static void doveadm_print_server_print(const char *value)
{
	str_tabescape_write(ctx.str, value);
	str_append_c(ctx.str, '\t');

	if (++ctx.header_idx == ctx.header_count) {
		ctx.header_idx = 0;
		doveadm_print_server_flush();
	}
}

static void
doveadm_print_server_print_stream(const unsigned char *value, size_t size)
{
	if (size == 0) {
		doveadm_print_server_print("");
		return;
	}
	T_BEGIN {
		str_tabescape_write(ctx.str, t_strndup(value, size));
	} T_END;

	if (str_len(ctx.str) >= IO_BLOCK_SIZE)
		doveadm_print_server_flush();
}

static void doveadm_print_server_flush(void)
{
	o_stream_send(client_connection_get_output(doveadm_client),
		      str_data(ctx.str), str_len(ctx.str));
	str_truncate(ctx.str, 0);
}

struct doveadm_print_vfuncs doveadm_print_server_vfuncs = {
	DOVEADM_PRINT_TYPE_SERVER,

	doveadm_print_server_init,
	doveadm_print_server_deinit,
	doveadm_print_server_header,
	doveadm_print_server_print,
	doveadm_print_server_print_stream,
	doveadm_print_server_flush
};
