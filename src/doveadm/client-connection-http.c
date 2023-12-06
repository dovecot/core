/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "compat.h"
#include "lib-signals.h"
#include "base64.h"
#include "ioloop.h"
#include "str.h"
#include "str-sanitize.h"
#include "istream.h"
#include "ostream.h"
#include "strescape.h"
#include "settings-parser.h"
#include "iostream-ssl.h"
#include "iostream-temp.h"
#include "istream-seekable.h"
#include "master-service.h"
#include "master-service-ssl.h"
#include "master-service-settings.h"
#include "mail-storage-service.h"
#include "http-server.h"
#include "http-request.h"
#include "http-response.h"
#include "http-url.h"
#include "doveadm-util.h"
#include "doveadm-mail.h"
#include "doveadm-print.h"
#include "doveadm-settings.h"
#include "client-connection-private.h"
#include "json-istream.h"
#include "json-ostream.h"

#include <unistd.h>
#include <ctype.h>

enum client_request_parse_state {
	CLIENT_REQUEST_PARSE_CMD = 0,
	CLIENT_REQUEST_PARSE_CMD_NAME,
	CLIENT_REQUEST_PARSE_CMD_PARAMS,
	CLIENT_REQUEST_PARSE_CMD_PARAM_KEY,
	CLIENT_REQUEST_PARSE_CMD_PARAM_VALUE,
	CLIENT_REQUEST_PARSE_CMD_PARAM_ARRAY,
	CLIENT_REQUEST_PARSE_CMD_PARAM_ISTREAM,
	CLIENT_REQUEST_PARSE_CMD_ID,
	CLIENT_REQUEST_PARSE_CMD_DONE,
	CLIENT_REQUEST_PARSE_DONE
};

struct client_request_http {
	pool_t pool;
	struct client_connection_http *conn;

	struct http_server_request *http_request;

	struct io *io;
	struct istream *input;
	struct ostream *output;

	struct json_istream *json_input;
	struct json_ostream *json_output;

	const struct doveadm_cmd_ver2 *cmd;
	struct doveadm_cmd_param *cmd_param;
	struct ioloop *ioloop;
	ARRAY_TYPE(doveadm_cmd_param_arr_t) pargv;
	int method_err;
	char *method_id;
	bool value_is_array;

	enum client_request_parse_state parse_state;
};

struct client_connection_http {
	struct client_connection conn;

	struct http_server_connection *http_conn;

	struct client_request_http *request;
};

typedef void doveadm_server_handler_t(struct client_request_http *req);

struct doveadm_http_server_mount {
	const char *verb;
	const char *path;
	doveadm_server_handler_t *handler;
	bool auth;
};

static void doveadm_http_server_send_response(struct client_request_http *req);

/*
 * API
 */

static void doveadm_http_server_options_handler(struct client_request_http *);
static void doveadm_http_server_print_mounts(struct client_request_http *);
static void doveadm_http_server_send_api_v1(struct client_request_http *);
static void doveadm_http_server_read_request_v1(struct client_request_http *);

static struct doveadm_http_server_mount doveadm_http_server_mounts[] = {
{
	.verb = "OPTIONS",
	.path = NULL,
	.handler = doveadm_http_server_options_handler,
	.auth = FALSE
},{
	.verb = "GET",
	.path = "/",
	.handler = doveadm_http_server_print_mounts,
	.auth = TRUE
},{
	.verb = "GET",
	.path = "/doveadm/v1",
	.handler = doveadm_http_server_send_api_v1,
	.auth = TRUE
},{
	.verb = "POST",
	.path = "/doveadm/v1",
	.handler = doveadm_http_server_read_request_v1,
	.auth = TRUE
}
};

static void doveadm_http_server_json_error(void *context, const char *error)
{
	struct client_request_http *req = context;
	struct json_ostream *json_output = req->json_output;

	json_ostream_ndescend_array(json_output, NULL);

	json_ostream_nwrite_string(json_output, NULL, "error");

	json_ostream_ndescend_object(json_output, NULL);
	json_ostream_nwrite_string(json_output, "type", error);
	json_ostream_nwrite_number(json_output, "exitCode",
				   doveadm_exit_code);
	json_ostream_nascend_object(json_output);

	if (req->method_id != NULL)
		json_ostream_nwrite_string(json_output, NULL, req->method_id);

	json_ostream_nascend_array(json_output);
}

static void
doveadm_http_server_json_success(void *context, struct istream *result)
{
	struct client_request_http *req = context;
	struct json_ostream *json_output = req->json_output;

	json_ostream_ndescend_array(json_output, NULL);
	json_ostream_nwrite_string(json_output, NULL, "doveadmResponse");

	json_ostream_nwrite_text_stream(json_output, NULL, result);

	if (req->method_id != NULL)
		json_ostream_nwrite_string(json_output, NULL, req->method_id);

	json_ostream_nascend_array(json_output);
}

static void
doveadm_http_server_command_execute(struct client_request_http *req)
{
	struct client_connection_http *conn = req->conn;
	struct istream *is;
	const char *user;
	struct ioloop *ioloop, *prev_ioloop;

	/* final preflight check */
	if (req->method_err == 0 &&
		!doveadm_client_is_allowed_command(conn->conn.set,
						   req->cmd->name))
		req->method_err = 403;
	if (req->method_err != 0) {
		if (req->method_err == 404) {
			doveadm_http_server_json_error(req, "unknownMethod");
		} else if (req->method_err == 403) {
			doveadm_http_server_json_error(req, "unAuthorized");
		} else if (req->method_err == 400) {
			doveadm_http_server_json_error(req, "invalidRequest");
		} else {
			doveadm_http_server_json_error(req, "internalError");
		}
		return;
	}

	prev_ioloop = current_ioloop;

	struct doveadm_cmd_context *cctx = doveadm_cmd_context_create(
		conn->conn.type, doveadm_verbose || doveadm_debug);

	cctx->input = req->input;
	cctx->output = req->output;

	// create iostream
	doveadm_print_ostream = iostream_temp_create("/tmp/doveadm.", 0);
	cctx->cmd = req->cmd;

	if ((cctx->cmd->flags & CMD_FLAG_NO_PRINT) == 0)
		doveadm_print_init(DOVEADM_PRINT_TYPE_JSON);

	/* then call it */
	doveadm_cmd_params_null_terminate_arrays(&req->pargv);
	cctx->argv = array_get(&req->pargv, (unsigned int*)&cctx->argc);
	ioloop = io_loop_create();
	doveadm_exit_code = 0;

	cctx->local_ip = conn->conn.local_ip;
	cctx->local_port = conn->conn.local_port;
	cctx->remote_ip = conn->conn.remote_ip;
	cctx->remote_port = conn->conn.remote_port;

	client_connection_set_proctitle(&conn->conn, cctx->cmd->name);
	event_set_append_log_prefix(cctx->event, t_strdup_printf(
		"cmd %s: ", cctx->cmd->name));

	if (doveadm_cmd_param_str(cctx, "user", &user))
		e_info(cctx->event, "Executing command as '%s'", user);
	else
		e_info(cctx->event, "Executing command");
	cctx->cmd->cmd(cctx);

	event_drop_parent_log_prefixes(cctx->event, 1);
	client_connection_set_proctitle(&conn->conn, "");

	o_stream_switch_ioloop_to(req->output, prev_ioloop);
	io_loop_destroy(&ioloop);

	if ((cctx->cmd->flags & CMD_FLAG_NO_PRINT) == 0)
		doveadm_print_deinit();
	if (o_stream_finish(doveadm_print_ostream) < 0) {
		e_info(cctx->event, "Error writing output in command %s: %s",
		       req->cmd->name,
		       o_stream_get_error(doveadm_print_ostream));
		doveadm_exit_code = EX_TEMPFAIL;
	}

	is = iostream_temp_finish(&doveadm_print_ostream, 4096);

	if (cctx->referral != NULL) {
		e_error(cctx->event,
			"Command requested referral: %s", cctx->referral);
		doveadm_http_server_json_error(req, "internalError");
	} else if (doveadm_exit_code != 0) {
		if (doveadm_exit_code == 0 || doveadm_exit_code == EX_TEMPFAIL) {
			e_error(cctx->event,
				"Command %s failed", req->cmd->name);
		}
		doveadm_http_server_json_error(req, "exitCode");
	} else {
		doveadm_http_server_json_success(req, is);
	}
	i_stream_unref(&is);
	doveadm_cmd_context_unref(&cctx);
}

static int request_json_parse_cmd(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	struct json_node jnode;
	int ret;

	ret = json_istream_descend(req->json_input, &jnode);
	if (ret <= 0)
		return ret;
	if (!json_node_is_array(&jnode)) {
		/* command must be an array */
		http_server_request_fail_text(http_sreq,
			400, "Bad Request",
			"Command must be a JSON array");
		return -1;
	}
	req->method_err = 0;
	p_free_and_null(req->pool, req->method_id);
	req->cmd = NULL;
	doveadm_cmd_params_clean(&req->pargv);

	/* next: parse the command name */
	req->parse_state = CLIENT_REQUEST_PARSE_CMD_NAME;
	return 1;
}

static int request_json_parse_cmd_name(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	struct json_node jnode;
	const struct doveadm_cmd_ver2 *ccmd;
	struct doveadm_cmd_param *param;
	const char *cmd_name;
	bool found;
	int pargc, ret;

	ret = json_istream_read_next(req->json_input, &jnode);
	if (ret <= 0)
		return ret;
	if (!json_node_is_string(&jnode)) {
		/* command name must be a string */
		http_server_request_fail_text(http_sreq,
			400, "Bad Request",
			"Command name must be a string");
		return -1;
	}

	/* see if we can find it */
	found = FALSE;
	cmd_name = json_node_get_str(&jnode);
	array_foreach(&doveadm_cmds_ver2, ccmd) {
		if (i_strccdascmp(ccmd->name, cmd_name) == 0) {
			req->cmd = ccmd;
			found = TRUE;
			break;
		}
	}
	if (!found) {
		/* command not found; skip to the command ID */
		json_istream_ignore(req->json_input, 1);
		req->method_err = 404;
		req->parse_state = CLIENT_REQUEST_PARSE_CMD_ID;
		return 1;
	}

	/* initialize pargv */
	for (pargc = 0; req->cmd->parameters[pargc].name != NULL; pargc++) {
		param = array_append_space(&req->pargv);
		*param = req->cmd->parameters[pargc];
		param->value_set = FALSE;
	}

	/* next: parse the command parameters */
	req->parse_state = CLIENT_REQUEST_PARSE_CMD_PARAMS;
	return 1;
}

static int request_json_parse_cmd_params(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	struct json_node jnode;
	int ret;

	ret = json_istream_descend(req->json_input, &jnode);
	if (ret <= 0)
		return ret;
	if (!json_node_is_object(&jnode)) {
		/* parameters must be contained in an object */
		http_server_request_fail_text(http_sreq,
			400, "Bad Request",
			"Parameters must be contained in a JSON object");
		return -1;
	}

	/* next: parse parameter key */
	req->parse_state = CLIENT_REQUEST_PARSE_CMD_PARAM_KEY;
	return 1;
}

static int request_json_parse_param_key(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	struct doveadm_cmd_param *par;
	const char *name;
	bool found;
	int ret;

	ret = json_istream_read_object_member(req->json_input, &name);
	if (ret <= 0)
		return ret;
	if (name == NULL) {
		/* end of parameters; parse command ID next */
		json_istream_ascend(req->json_input);
		req->parse_state = CLIENT_REQUEST_PARSE_CMD_ID;
		return 1;
	}
	/* find the parameter */
	found = FALSE;
	array_foreach_modifiable(&req->pargv, par) {
		if (i_strccdascmp(par->name, name) == 0) {
			req->cmd_param = par;
			found = TRUE;
			break;
		}
	}
	if (found && req->cmd_param->value_set) {
		/* it's already set, cannot have same key twice in json */
		http_server_request_fail_text(http_sreq,
			400, "Bad Request",
			"Parameter `%s' is duplicated",
			req->cmd_param->name);
		return -1;
	}
	/* skip remaining parameters if error has already occurred */
	if (!found || req->method_err != 0) {
		json_istream_ascend(req->json_input);
		req->method_err = 400;
		req->parse_state = CLIENT_REQUEST_PARSE_CMD_ID;
		return 1;
	}

	/* next: continue with the value */
	req->value_is_array = FALSE;
	req->parse_state = CLIENT_REQUEST_PARSE_CMD_PARAM_VALUE;
	return 1;
}

static int request_json_parse_param_value(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	struct json_node jnode;
	const char *value;
	int ret;

	if (req->cmd_param->type == CMD_PARAM_ISTREAM) {
		/* read the value as a stream */
		ret = json_istream_read_stream(req->json_input, 0,
					       IO_BLOCK_SIZE, "/tmp/doveadm.",
					       &jnode);
		if (ret <= 0)
			return ret;
		if (!json_node_is_string(&jnode)) {
			http_server_request_fail_text(http_sreq,
				400, "Bad Request",
				"Parameter `%s' must be a string",
				req->cmd_param->name);
			return -1;
		}

		i_assert(jnode.value.content_type == JSON_CONTENT_TYPE_STREAM);
		req->cmd_param->value.v_istream = jnode.value.content.stream;
		i_stream_ref(req->cmd_param->value.v_istream);
		req->cmd_param->value_set = TRUE;

		/* next: continue with the next parameter */
		json_istream_skip(req->json_input);
		req->parse_state = CLIENT_REQUEST_PARSE_CMD_PARAM_KEY;
		return 1;
	}

	ret = json_istream_descend(req->json_input, &jnode);
	if (ret <= 0)
		return ret;
	if (req->cmd_param->type == CMD_PARAM_ARRAY) {
		/* expects either a singular value or an array of values */
		p_array_init(&req->cmd_param->value.v_array, req->pool, 1);
		req->cmd_param->value_set = TRUE;
		if (json_node_is_array(&jnode)) {
			/* start of array */
			req->value_is_array = TRUE;
			req->parse_state = CLIENT_REQUEST_PARSE_CMD_PARAM_ARRAY;
			return 1;
		}
		/* singular value */
		if (!json_node_is_string(&jnode)) {
			/* FIXME: should handle other than string too */
			http_server_request_fail_text(http_sreq,
				400, "Bad Request",
				"Parameter `%s' must be string or array",
				req->cmd_param->name);
			return -1;
		}
		value = p_strdup(req->pool, json_node_get_str(&jnode));
		array_push_back(&req->cmd_param->value.v_array, &value);

		/* next: continue with the next parameter */
		req->parse_state = CLIENT_REQUEST_PARSE_CMD_PARAM_KEY;
		return 1;
	}

	/* expects just a value */
	value = json_node_get_str(&jnode);
	req->cmd_param->value_set = TRUE;
	switch(req->cmd_param->type) {
	case CMD_PARAM_BOOL:
		if (strcmp(value, "true") == 0) {
			req->cmd_param->value.v_bool = TRUE;
		} else if (strcmp(value, "false") == 0) {
			req->cmd_param->value.v_bool = FALSE;
		} else {
			http_server_request_fail_text(http_sreq,
				400, "Bad Request",
				"Parameter `%s' must be `true' or `false', not `%s'",
				req->cmd_param->name, value);
			return -1;
		}
		break;
	case CMD_PARAM_INT64:
		if (str_to_int64(value, &req->cmd_param->value.v_int64) != 0)
			req->method_err = 400;
		break;
	case CMD_PARAM_IP:
		if (net_addr2ip(value, &req->cmd_param->value.v_ip) != 0)
			req->method_err = 400;
		break;
	case CMD_PARAM_STR:
		req->cmd_param->value.v_string = p_strdup(req->pool, value);
		break;
	default:
		break;
	}

	/* next: continue with the next parameter */
	req->parse_state = CLIENT_REQUEST_PARSE_CMD_PARAM_KEY;
	return 1;
}

static int request_json_parse_param_array(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	struct json_node jnode;
	const char *tmp;
	int ret;

	ret = json_istream_read_next(req->json_input, &jnode);
	if (ret <= 0)
		return ret;
	if (json_node_is_array_end(&jnode)) {
		/* end of array: continue with next parameter */
		json_istream_ascend(req->json_input);
		req->parse_state = CLIENT_REQUEST_PARSE_CMD_PARAM_KEY;
		return 1;
	}
	if (!json_node_is_string(&jnode)) {
		/* array items must be string */
		http_server_request_fail_text(http_sreq,
			400, "Bad Request",
			"Command parameter array can only contain"
			"string values");
		return -1;
	}

	/* record entry */
	tmp = p_strdup(req->pool, json_node_get_str(&jnode));
	array_push_back(&req->cmd_param->value.v_array, &tmp);

	/* next: continue with the next array item */
	return 1;
}

static int request_json_parse_cmd_id(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	struct json_node jnode;
	int ret;

	ret = json_istream_read_next(req->json_input, &jnode);
	if (ret <= 0)
		return ret;
	if (!json_node_is_string(&jnode)) {
		/* command ID must be a string */
		http_server_request_fail_text(http_sreq,
			400, "Bad Request",
			"Command ID must be a string");
		return -1;
	}

	/* next: parse end of command */
	req->method_id = p_strdup(req->pool, json_node_get_str(&jnode));
	req->parse_state = CLIENT_REQUEST_PARSE_CMD_DONE;
	return 1;
}

static int request_json_parse_cmd_done(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	struct json_node jnode;
	int ret;

	ret = json_istream_read_next(req->json_input, &jnode);
	if (ret <= 0)
		return ret;
	if (!json_node_is_array_end(&jnode)) {
		/* command array must end here */
		http_server_request_fail_text(http_sreq,
			400, "Bad Request",
			"Unexpected JSON element at end of command");
		return -1;
	}
	json_istream_ascend(req->json_input);

	/* execute command */
	doveadm_http_server_command_execute(req);

	/* next: parse next command */
	req->parse_state = CLIENT_REQUEST_PARSE_CMD;
	return 1;
}

static int request_json_parse_done(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	struct json_node jnode;
	int ret;

	ret = json_istream_read_next(req->json_input, &jnode);
	if (ret <= 0)
		return ret;
	/* only gets here when there is spurious additional JSON */
	http_server_request_fail_text(http_sreq,
		400, "Bad Request",
		"Unexpected JSON element in input");
	return -1;
}

static int doveadm_http_server_json_parse_v1(struct client_request_http *req)
{
	/* parser state machine */
	switch (req->parse_state) {
	/* command begin: '[' */
	case CLIENT_REQUEST_PARSE_CMD:
		return request_json_parse_cmd(req);
	/* command name: string */
	case CLIENT_REQUEST_PARSE_CMD_NAME:
		return request_json_parse_cmd_name(req);
	/* command parameters: '{' */
	case CLIENT_REQUEST_PARSE_CMD_PARAMS:
		return request_json_parse_cmd_params(req);
	/* parameter key */
	case CLIENT_REQUEST_PARSE_CMD_PARAM_KEY:
		return request_json_parse_param_key(req);
	/* parameter value: string */
	case CLIENT_REQUEST_PARSE_CMD_PARAM_VALUE:
		return request_json_parse_param_value(req);
	/* parameter array value */
	case CLIENT_REQUEST_PARSE_CMD_PARAM_ARRAY:
		return request_json_parse_param_array(req);
	/* command ID: string */
	case CLIENT_REQUEST_PARSE_CMD_ID:
		return request_json_parse_cmd_id(req);
	/* command end: ']' */
	case CLIENT_REQUEST_PARSE_CMD_DONE:
		return request_json_parse_cmd_done(req);
	/* finished parsing request (seen final ']') */
	case CLIENT_REQUEST_PARSE_DONE:
		return request_json_parse_done(req);
	default:
		break;
	}
	i_unreached();
}

static bool
doveadm_http_server_finish_json_output(struct client_request_http *req,
				       struct json_ostream **_json_output)
{
	struct http_server_request *http_sreq = req->http_request;
	struct json_ostream *json_output = *_json_output;
	bool result = TRUE;

	if (json_ostream_nfinish(json_output) < 0) {
		e_error(req->conn->conn.event,
			"error writing JSON output: %s",
			json_ostream_get_error(json_output));
		http_server_request_fail(http_sreq,
					 500, "Internal server error");
		result = FALSE;
	}
	json_ostream_destroy(_json_output);

	return result;
}

static void
doveadm_http_server_read_request_v1(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	const char *error;
	int ret;

	if (req->json_input == NULL) {
		req->json_input = json_istream_create_array(
			req->input, NULL, JSON_PARSER_FLAG_NUMBERS_AS_STRING);
	}

	if (req->json_output == NULL) {
		req->json_output = json_ostream_create(req->output, 0);
		json_ostream_set_no_error_handling(req->json_output, TRUE);
		json_ostream_ndescend_array(req->json_output, NULL);
	}

	while ((ret = doveadm_http_server_json_parse_v1(req)) > 0);

	if (http_server_request_get_response(http_sreq) != NULL) {
		/* already responded */
		json_istream_destroy(&req->json_input);
		io_remove(&req->io);
		i_stream_destroy(&req->input);
		return;
	}
	if (!req->input->eof && ret == 0)
		return;
	io_remove(&req->io);

	doveadm_cmd_params_clean(&req->pargv);

	if (req->input->stream_errno != 0) {
		http_server_request_fail_close(http_sreq,
			400, "Client disconnected");
		e_info(req->conn->conn.event,
			"read(%s) failed: %s",
		       i_stream_get_name(req->input),
		       i_stream_get_error(req->input));
		return;
	}

	ret = json_istream_finish(&req->json_input, &error);
	i_assert(ret != 0);
	if (ret < 0) {
		http_server_request_fail_text(http_sreq,
			400, "Bad Request",
			"JSON parse error: %s", error);
		return;
	}

	json_ostream_nascend_array(req->json_output);
	if (!doveadm_http_server_finish_json_output(req, &req->json_output))
		return;

	doveadm_http_server_send_response(req);
}

static const char *
doveadm_http_server_camelcase_value(string_t *tmp, const char *value)
{
	const char *p, *poffset;

	str_truncate(tmp, 0);

	poffset = p = value;
	while (*p != '\0') {
		if (*p == ' ' || *p == '-') {
			if (p > poffset)
				str_append_data(tmp, poffset, p - poffset);
			do {
				p++;
			} while (*p == ' ' || *p == '-');
			if (*p == '\0')
				break;
			str_append_c(tmp, i_toupper(*p));
			p++;
			poffset = p;
		} else {
			p++;
		}
	}
	if (p > poffset)
		str_append_data(tmp, poffset, p - poffset);
	return str_c(tmp);
}

static void doveadm_http_server_send_api_v1(struct client_request_http *req)
{
	struct json_ostream *json_output;
	const struct doveadm_cmd_ver2 *cmd;
	const struct doveadm_cmd_param *par;
	unsigned int i, k;
	string_t *cctmp;

	cctmp = t_str_new(64);

	json_output = json_ostream_create(req->output, 0);
	json_ostream_set_no_error_handling(json_output, TRUE);
	json_ostream_ndescend_array(json_output, NULL);

	for (i = 0; i < array_count(&doveadm_cmds_ver2); i++) {
		cmd = array_idx(&doveadm_cmds_ver2, i);
		if ((cmd->flags & CMD_FLAG_HIDDEN) != 0)
			continue;

		json_ostream_ndescend_object(json_output, NULL);
		json_ostream_nwrite_string(
			json_output, "command",
			doveadm_http_server_camelcase_value(cctmp, cmd->name));

		json_ostream_ndescend_array(json_output, "parameters");

		for (k = 0; cmd->parameters[k].name != NULL; k++) {
			par = &(cmd->parameters[k]);
			if ((par->flags & CMD_PARAM_FLAG_DO_NOT_EXPOSE) != 0)
				continue;
			json_ostream_ndescend_object(json_output, NULL);
			json_ostream_nwrite_string(
				json_output, "name",
				doveadm_http_server_camelcase_value(cctmp,
								    par->name));
			switch(par->type) {
			case CMD_PARAM_BOOL:
				json_ostream_nwrite_string(json_output,
							   "type", "boolean");
				break;
			case CMD_PARAM_INT64:
				json_ostream_nwrite_string(json_output,
							   "type", "integer");
				break;
			case CMD_PARAM_ARRAY:
				json_ostream_nwrite_string(json_output,
							   "type", "array");
				break;
			case CMD_PARAM_IP:
			case CMD_PARAM_ISTREAM:
			case CMD_PARAM_STR:
				json_ostream_nwrite_string(json_output,
							   "type", "string");
			}
			json_ostream_nascend_object(json_output);
		}
		json_ostream_nascend_array(json_output);
		json_ostream_nascend_object(json_output);
	}

	json_ostream_nascend_array(json_output);
	if (!doveadm_http_server_finish_json_output(req, &json_output))
		return;

	doveadm_http_server_send_response(req);
}

static void
doveadm_http_server_options_handler(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	struct http_server_response *http_resp;

	http_resp = http_server_response_create(http_sreq, 200, "OK");
	http_server_response_add_header(http_resp,
		"Access-Control-Allow-Origin", "*");
	http_server_response_add_header(http_resp,
		"Access-Control-Allow-Methods", "GET, POST, OPTIONS");
	http_server_response_add_header(http_resp,
		"Access-Control-Allow-Request-Headers",
		"Content-Type, X-API-Key, Authorization");
	http_server_response_add_header(http_resp,
		"Access-Control-Allow-Headers",
		"Content-Type, WWW-Authenticate");
	http_server_response_submit(http_resp);
}

static void doveadm_http_server_print_mounts(struct client_request_http *req)
{
	struct json_ostream *json_output;
	unsigned int i;

	json_output = json_ostream_create(req->output, 0);
	json_ostream_set_no_error_handling(json_output, TRUE);
	json_ostream_ndescend_array(json_output, NULL);

	for (i = 0; i < N_ELEMENTS(doveadm_http_server_mounts); i++) {
		json_ostream_ndescend_object(json_output, NULL);

		if (doveadm_http_server_mounts[i].verb == NULL) {
			json_ostream_nwrite_string(json_output, "method", "*");
		} else {
			json_ostream_nwrite_string(
				json_output, "method",
				doveadm_http_server_mounts[i].verb);
		}
		if (doveadm_http_server_mounts[i].path == NULL) {
			json_ostream_nwrite_string(json_output, "path", "*");
		} else {
			json_ostream_nwrite_string(
				json_output, "path",
				doveadm_http_server_mounts[i].path);
		}

		json_ostream_nascend_object(json_output);
	}

	json_ostream_nascend_array(json_output);
	if (!doveadm_http_server_finish_json_output(req, &json_output))
		return;

	doveadm_http_server_send_response(req);
}

/*
 * Request
 */

static void doveadm_http_server_send_response(struct client_request_http *req)
{
	struct http_server_request *http_sreq = req->http_request;
	struct http_server_response *http_resp;
	struct istream *payload = NULL;

	if (req->output != NULL) {
		if (o_stream_finish(req->output) == -1) {
			e_info(req->conn->conn.event,
			       "error writing output: %s",
			       o_stream_get_error(req->output));
			o_stream_destroy(&req->output);
			http_server_request_fail(http_sreq,
				500, "Internal server error");
			return;
		}

		payload = iostream_temp_finish(&req->output,
					       IO_BLOCK_SIZE);
	}

	http_resp = http_server_response_create(http_sreq, 200, "OK");
	http_server_response_add_header(http_resp, "Content-Type",
		"application/json; charset=utf-8");

	if (payload != NULL) {
		http_server_response_set_payload(http_resp, payload);
		i_stream_unref(&payload);
	}

	http_server_response_submit(http_resp);
}

static void
doveadm_http_server_request_destroy(struct client_request_http *req)
{
	struct client_connection_http *conn = req->conn;
	struct http_server_request *http_sreq = req->http_request;
	const struct http_request *http_req =
		http_server_request_get(http_sreq);
	struct http_server_response *http_resp =
		http_server_request_get_response(http_sreq);

	i_assert(conn->request == req);

	if (http_resp != NULL) {
		const char *agent, *url, *reason;
		uoff_t size;
		int status;

		http_server_response_get_status(http_resp, &status, &reason);
		size = http_server_response_get_total_size(http_resp);
		agent = http_request_header_get(http_req, "User-Agent");
		if (agent == NULL) agent = "";

		url = http_url_create(http_req->target.url);
		e_info(conn->conn.event, "doveadm: %s %s %s \"%s %s "
		       "HTTP/%d.%d\" %d %"PRIuUOFF_T" \"%s\" \"%s\"",
		       net_ip2addr(&conn->conn.remote_ip), "-", "-",
		       http_req->method, http_req->target.url->path,
		       http_req->version_major, http_req->version_minor,
		       status, size, url, agent);
	}
	json_istream_destroy(&req->json_input);
	json_ostream_destroy(&req->json_output);
	if (req->output != NULL)
		o_stream_set_no_error_handling(req->output, TRUE);
	io_remove(&req->io);
	o_stream_destroy(&req->output);
	i_stream_destroy(&req->input);

	http_server_request_unref(&req->http_request);
	http_server_switch_ioloop(http_server_request_get_server(http_sreq));

	pool_unref(&req->pool);
	conn->request = NULL;
}

static bool
doveadm_http_server_auth_basic(struct client_request_http *req,
			       const struct http_auth_credentials *creds)
{
	struct client_connection_http *conn = req->conn;
	const struct doveadm_settings *set = conn->conn.set;
	string_t *b64_value;
	char *value;

	if (*set->doveadm_password == '\0') {
		e_error(conn->conn.event,
			"Invalid authentication attempt to HTTP API: "
			"Basic authentication scheme not enabled");
		return FALSE;
	}

	b64_value = str_new(conn->conn.pool, 32);
	value = p_strdup_printf(conn->conn.pool,
				"doveadm:%s", set->doveadm_password);
	base64_encode(value, strlen(value), b64_value);
	if (creds->data != NULL && strcmp(creds->data, str_c(b64_value)) == 0)
		return TRUE;

	e_error(conn->conn.event,
		"Invalid authentication attempt to HTTP API "
		"(using Basic authentication scheme)");
	return FALSE;
}

static bool
doveadm_http_server_auth_api_key(struct client_request_http *req,
				 const struct http_auth_credentials *creds)
{
	struct client_connection_http *conn = req->conn;
	const struct doveadm_settings *set = doveadm_settings;
	string_t *b64_value;

	if (*set->doveadm_api_key == '\0') {
		e_error(conn->conn.event,
			"Invalid authentication attempt to HTTP API: "
			"X-Dovecot-API authentication scheme not enabled");
		return FALSE;
	}

	b64_value = str_new(conn->conn.pool, 32);
	base64_encode(set->doveadm_api_key,
		      strlen(set->doveadm_api_key), b64_value);
	if (creds->data != NULL && strcmp(creds->data, str_c(b64_value)) == 0)
		return TRUE;

	e_error(conn->conn.event,
		"Invalid authentication attempt to HTTP API "
		"(using X-Dovecot-API authentication scheme)");
	return FALSE;
}


static bool
doveadm_http_server_auth_verify(struct client_request_http *req,
				const struct http_auth_credentials *creds)
{
	/* see if the mech is supported */
	if (strcasecmp(creds->scheme, "Basic") == 0)
		return doveadm_http_server_auth_basic(req, creds);
	if (strcasecmp(creds->scheme, "X-Dovecot-API") == 0)
		return doveadm_http_server_auth_api_key(req, creds);

	e_error(req->conn->conn.event,
		"Unsupported authentication scheme to HTTP API: %s",
		str_sanitize(creds->scheme, 128));
	return FALSE;
}

static bool
doveadm_http_server_authorize_request(struct client_request_http *req)
{
	struct client_connection_http *conn = req->conn;
	struct http_server_request *http_sreq = req->http_request;
	bool auth = FALSE;
	struct http_auth_credentials creds;

	/* no authentication specified */
	if (doveadm_settings->doveadm_api_key[0] == '\0' &&
		*conn->conn.set->doveadm_password == '\0') {
		http_server_request_fail(http_sreq,
			500, "Internal Server Error");
		e_error(conn->conn.event,
			"No authentication defined in configuration. "
			"Add API key or password");
		return FALSE;
	}
	if (http_server_request_get_auth(http_sreq, &creds) > 0)
		auth = doveadm_http_server_auth_verify(req, &creds);
	if (!auth) {
		struct http_server_response *http_resp;

		http_resp = http_server_response_create(http_sreq,
			401, "Authentication required");
		if (doveadm_settings->doveadm_api_key[0] != '\0') {
			http_server_response_add_header(http_resp,
				"WWW-Authenticate", "X-Dovecot-API"
			);
		}
		if (*conn->conn.set->doveadm_password != '\0') {
			http_server_response_add_header(http_resp,
				"WWW-Authenticate", "Basic Realm=\"doveadm\""
			);
		}
		http_server_response_submit(http_resp);
	}
	return auth;
}

static void
doveadm_http_server_handle_request(void *context,
				   struct http_server_request *http_sreq)
{
	struct client_connection_http *conn = context;
	struct client_request_http *req;
	const struct http_request *http_req =
		http_server_request_get(http_sreq);
	struct doveadm_http_server_mount *ep = NULL;
	pool_t pool;
	unsigned int i;

	/* no pipelining possible due to synchronous handling of requests */
	i_assert(conn->request == NULL);

	pool = pool_alloconly_create("doveadm request", 1024*16);
	req = p_new(pool, struct client_request_http, 1);
	req->pool = pool;
	req->conn = conn;

	req->http_request = http_sreq;
	http_server_request_ref(req->http_request);

	http_server_request_connection_close(http_sreq, TRUE);
	http_server_request_set_destroy_callback(http_sreq,
		doveadm_http_server_request_destroy, req);

	conn->request = req;

	for (i = 0; i < N_ELEMENTS(doveadm_http_server_mounts); i++) {
		if (doveadm_http_server_mounts[i].verb == NULL ||
		    strcmp(http_req->method,
			   doveadm_http_server_mounts[i].verb) == 0) {
			if (doveadm_http_server_mounts[i].path == NULL ||
                            strcmp(http_req->target.url->path,
				   doveadm_http_server_mounts[i].path) == 0) {
				ep = &doveadm_http_server_mounts[i];
				break;
			}
		}
	}

	if (ep == NULL) {
		http_server_request_fail(http_sreq, 404, "Path Not Found");
		return;
	}

 	if (ep->auth == TRUE && !doveadm_http_server_authorize_request(req))
		return;

	if (strcmp(http_req->method, "POST") == 0) {
		/* handle request */
		req->input = http_req->payload;
		i_stream_set_name(req->input,
				  net_ip2addr(&conn->conn.remote_ip));
		i_stream_ref(req->input);
		req->io = io_add_istream(req->input, *ep->handler, req);
		req->output = iostream_temp_create_named(
			"/tmp/doveadm.", 0, net_ip2addr(&conn->conn.remote_ip));
		p_array_init(&req->pargv, req->pool, 5);
		ep->handler(req);
	} else {
		req->output = iostream_temp_create_named(
			"/tmp/doveadm.", 0, net_ip2addr(&conn->conn.remote_ip));
		ep->handler(req);
	}
}

/*
 * Connection
 */

static void doveadm_http_server_connection_destroy(void *context,
						   const char *reason);

static const struct http_server_callbacks doveadm_http_callbacks = {
        .connection_destroy = doveadm_http_server_connection_destroy,
        .handle_request = doveadm_http_server_handle_request
};

static void client_connection_http_free(struct client_connection *_conn)
{
	struct client_connection_http *conn =
		(struct client_connection_http *)_conn;

	if (conn->http_conn != NULL) {
		/* We're not in the lib-http/server's connection destroy
		   callback. */
		http_server_connection_close(&conn->http_conn,
			MASTER_SERVICE_SHUTTING_DOWN_MSG);
	}
}

struct client_connection *
client_connection_http_create(struct http_server *doveadm_http_server, int fd,
			      bool ssl)
{
	struct client_connection_http *conn;
	pool_t pool;

	pool = pool_alloconly_create("doveadm client", 1024);
	conn = p_new(pool, struct client_connection_http, 1);
	conn->conn.event = event_create(NULL);
	event_set_append_log_prefix(conn->conn.event, "http: ");

	if (client_connection_init(&conn->conn,
		DOVEADM_CONNECTION_TYPE_HTTP, pool, fd) < 0) {
		pool_unref(&conn->conn.pool);
		return NULL;
	}
	conn->conn.free = client_connection_http_free;

	conn->http_conn = http_server_connection_create(doveadm_http_server,
			fd, fd, ssl, &doveadm_http_callbacks, conn);
	return &conn->conn;
}

static void
doveadm_http_server_connection_destroy(void *context,
				       const char *reason ATTR_UNUSED)
{
	struct client_connection_http *conn =
		(struct client_connection_http *)context;
	struct client_connection *bconn = &conn->conn;

	if (conn->http_conn == NULL) {
		/* already destroying client directly */
		return;
	}

	/* HTTP connection is destroyed already now */
	conn->http_conn = NULL;

	/* destroy the connection itself */
	client_connection_destroy(&bconn);
}
