/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "imap-common.h"
#include "str.h"
#include "istream.h"
#include "ostream.h"
#include "module-context.h"
#include "imap-commands.h"
#include "compression.h"
#include "imap-zlib-plugin.h"


#define IMAP_COMPRESS_DEFAULT_LEVEL 6

#define IMAP_ZLIB_IMAP_CONTEXT(obj) \
	MODULE_CONTEXT_REQUIRE(obj, imap_zlib_imap_module)

struct zlib_client {
	union imap_module_context module_ctx;

	int (*next_state_export)(struct client *client, bool internal,
				 buffer_t *dest, const char **error_r);
	const struct compression_handler *handler;
};

const char *imap_zlib_plugin_version = DOVECOT_ABI_VERSION;

static struct module *imap_zlib_module;
static imap_client_created_func_t *next_hook_client_created;

static MODULE_CONTEXT_DEFINE_INIT(imap_zlib_imap_module,
				  &imap_module_register);

static void client_skip_line(struct client *client)
{
	const unsigned char *data;
	size_t data_size;

	data = i_stream_get_data(client->input, &data_size);
	i_assert(data_size > 0);
	if (data[0] == '\n')
		i_stream_skip(client->input, 1);
	else if (data[0] == '\r' && data_size > 1 && data[1] == '\n')
		i_stream_skip(client->input, 2);
	else
		i_unreached();
	client->input_skip_line = FALSE;
}

static void client_update_imap_parser_streams(struct client *client)
{
	struct client_command_context *cmd;

	if (client->free_parser != NULL) {
		imap_parser_set_streams(client->free_parser,
					client->input, client->output);
	}

	for (cmd = client->command_queue; cmd != NULL; cmd = cmd->next) {
		imap_parser_set_streams(cmd->parser,
					client->input, client->output);
	}
}

static bool cmd_compress(struct client_command_context *cmd)
{
	struct client *client = cmd->client;
	struct zlib_client *zclient = IMAP_ZLIB_IMAP_CONTEXT(client);
	const struct compression_handler *handler;
	const struct imap_arg *args;
	struct istream *old_input;
	struct ostream *old_output;
	const char *mechanism, *value;
	unsigned int level;
	int ret;

	/* <mechanism> */
	if (!client_read_args(cmd, 0, 0, &args))
		return FALSE;

	if (!imap_arg_get_atom(args, &mechanism) ||
	    !IMAP_ARG_IS_EOL(&args[1])) {
		client_send_command_error(cmd, "Invalid arguments.");
		return TRUE;
	}
	if (zclient->handler != NULL) {
		client_send_tagline(cmd, t_strdup_printf(
			"NO [COMPRESSIONACTIVE] COMPRESSION=%s already enabled.",
			t_str_ucase(zclient->handler->name)));
		return TRUE;
	}

	ret = compression_lookup_handler(t_str_lcase(mechanism), &handler);
	if (ret <= 0) {
		const char * tagline =
			t_strdup_printf("NO %s compression mechanism",
					ret == 0 ? "Unsupported" : "Unknown");
		client_send_tagline(cmd, tagline);
		return TRUE;
	}

	client_skip_line(client);
	client_send_tagline(cmd, "OK Begin compression.");

	value = mail_user_plugin_getenv(client->user,
					"imap_zlib_compress_level");
	if (value == NULL || str_to_uint(value, &level) < 0 ||
	    level <= 0 || level > 9)
		level = IMAP_COMPRESS_DEFAULT_LEVEL;

	old_input = client->input;
	old_output = client->output;
	client->input = handler->create_istream(old_input, FALSE);
	client->output = handler->create_ostream(old_output, level);
	/* preserve output offset so that the bytes out counter in logout
	   message doesn't get reset here */
	client->output->offset = old_output->offset;
	i_stream_unref(&old_input);
	o_stream_unref(&old_output);

	client_update_imap_parser_streams(client);
	zclient->handler = handler;
	return TRUE;
}

static int
imap_zlib_state_export(struct client *client, bool internal,
		       buffer_t *dest, const char **error_r)
{
	struct zlib_client *zclient = IMAP_ZLIB_IMAP_CONTEXT(client);

	if (zclient->handler != NULL && internal) {
		*error_r = "COMPRESS enabled";
		return 0;
	}
	return zclient->next_state_export(client, internal, dest, error_r);
}

static void imap_zlib_client_created(struct client **clientp)
{
	struct client *client = *clientp;
	struct zlib_client *zclient;
	const struct compression_handler *handler;

	if (mail_user_is_plugin_loaded(client->user, imap_zlib_module) &&
	    compression_lookup_handler("deflate", &handler) > 0) {
		zclient = p_new(client->pool, struct zlib_client, 1);
		MODULE_CONTEXT_SET(client, imap_zlib_imap_module, zclient);

		zclient->next_state_export = (*clientp)->v.state_export;
		(*clientp)->v.state_export = imap_zlib_state_export;

		client_add_capability(*clientp, "COMPRESS=DEFLATE");
	}

	if (next_hook_client_created != NULL)
		next_hook_client_created(clientp);
}

void imap_zlib_plugin_init(struct module *module)
{
	command_register("COMPRESS", cmd_compress, 0);

	imap_zlib_module = module;
	next_hook_client_created =
		imap_client_created_hook_set(imap_zlib_client_created);
}

void imap_zlib_plugin_deinit(void)
{
	command_unregister("COMPRESS");

	imap_client_created_hook_set(next_hook_client_created);
}

const char imap_zlib_plugin_binary_dependency[] = "imap";
