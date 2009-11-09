/* Copyright (c) 2009 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "hostpid.h"
#include "istream.h"
#include "istream-concat.h"
#include "ostream.h"
#include "istream-dot.h"
#include "safe-mkstemp.h"
#include "master-service.h"
#include "rfc822-parser.h"
#include "message-date.h"
#include "auth-master.h"
#include "mail-storage-service.h"
#include "index/raw/raw-storage.h"
#include "lda-settings.h"
#include "lmtp-settings.h"
#include "mail-deliver.h"
#include "main.h"
#include "client.h"
#include "commands.h"
#include "lmtp-proxy.h"

#include <stdlib.h>

#define ERRSTR_TEMP_MAILBOX_FAIL "451 4.3.0 <%s> Temporary internal error"
#define ERRSTR_TEMP_USERDB_FAIL "451 4.3.0 <%s> Temporary user lookup failure"

#define LMTP_PROXY_DEFAULT_TIMEOUT_MSECS (1000*30)

int cmd_lhlo(struct client *client, const char *args)
{
	struct rfc822_parser_context parser;
	string_t *domain = t_str_new(128);
	const char *p;
	int ret = 0;

	if (*args == '\0') {
		client_send_line(client, "501 Missing hostname");
		return 0;
	}

	/* domain / address-literal */
	rfc822_parser_init(&parser, (const unsigned char *)args, strlen(args),
			   NULL);
	if (*args != '[')
		ret = rfc822_parse_dot_atom(&parser, domain);
	else {
		for (p = args+1; *p != ']'; p++) {
			if (*p == '\\' || *p == '[')
				break;
		}
		if (strcmp(p, "]") != 0)
			ret = -1;
	}
	if (ret < 0) {
		str_truncate(domain, 0);
		str_append(domain, "invalid");
	}

	client_state_reset(client);
	client_send_line(client, "250-%s", client->my_domain);
	client_send_line(client, "250-8BITMIME");
	client_send_line(client, "250-ENHANCEDSTATUSCODES");
	client_send_line(client, "250 PIPELINING");

	client->state.lhlo = p_strdup(client->state_pool, str_c(domain));
	return 0;
}

int cmd_mail(struct client *client, const char *args)
{
	const char *addr, *const *argv;
	unsigned int len;

	if (client->state.mail_from != NULL) {
		client_send_line(client, "503 5.5.1 MAIL already given");
		return 0;
	}

	argv = t_strsplit(args, " ");
	if (argv == NULL)
		addr = "";
	else {
		addr = argv[0];
		argv++;
	}
	len = strlen(addr);
	if (strncasecmp(addr, "FROM:<", 6) != 0 || addr[len-1] != '>') {
		client_send_line(client, "501 5.5.4 Invalid parameters");
		return 0;
	}

	for (; *argv != NULL; argv++) {
		if (strcasecmp(*argv, "BODY=7BIT") == 0)
			client->mail_body_7bit = TRUE;
		else if (strcasecmp(*argv, "BODY=8BITMIME") == 0)
			client->mail_body_8bitmime = TRUE;
		else {
			client_send_line(client,
				"501 5.5.4 Unsupported options");
			return 0;
		}
	}

	client->state.mail_from =
		p_strndup(client->state_pool, addr + 6, len - 7);
	p_array_init(&client->state.rcpt_to, client->state_pool, 64);
	client_send_line(client, "250 2.1.0 OK");
	return 0;
}

static bool rcpt_is_duplicate(struct client *client, const char *name)
{
	const struct mail_recipient *rcpt;

	array_foreach(&client->state.rcpt_to, rcpt) {
		if (strcmp(rcpt->name, name) == 0)
			return TRUE;
	}
	return FALSE;
}

static bool
client_proxy_rcpt_parse_fields(struct lmtp_proxy_settings *set,
			       const char *const *args, const char **address)
{
	const char *p, *key, *value;
	bool proxying = FALSE, port_set = FALSE;

	for (; *args != NULL; args++) {
		p = strchr(*args, '=');
		if (p == NULL) {
			key = *args;
			value = "";
		} else {
			key = t_strdup_until(*args, p);
			value = p + 1;
		}

		if (strcmp(key, "proxy") == 0)
			proxying = TRUE;
		else if (strcmp(key, "host") == 0)
			set->host = value;
		else if (strcmp(key, "port") == 0) {
			set->port = atoi(value);
			port_set = TRUE;
		} else if (strcmp(key, "proxy_timeout") == 0)
			set->timeout_msecs = atoi(value)*1000;
		else if (strcmp(key, "protocol") == 0) {
			if (strcmp(value, "lmtp") == 0)
				set->protocol = LMTP_CLIENT_PROTOCOL_LMTP;
			else if (strcmp(value, "smtp") == 0) {
				set->protocol = LMTP_CLIENT_PROTOCOL_SMTP;
				if (!port_set)
					set->port = 25;
			} else {
				i_error("proxy: Unknown protocol %s", value);
				return FALSE;
			}
		} else if (strcmp(key, "user") == 0) {
			/* changing the username */
			*address = value;
		} else {
			/* just ignore it */
		}
	}
	if (proxying && set->host == NULL) {
		i_error("proxy: host not given");
		return FALSE;
	}
	return proxying;
}

static bool
client_proxy_is_ourself(const struct client *client,
			const struct lmtp_proxy_settings *set)
{
	struct ip_addr ip;

	if (set->port != client->local_port)
		return FALSE;

	if (net_addr2ip(set->host, &ip) < 0)
		return FALSE;
	if (!net_ip_compare(&ip, &client->local_ip))
		return FALSE;
	return TRUE;
}

static bool client_proxy_rcpt(struct client *client, const char *address)
{
	struct auth_master_connection *auth_conn;
	struct lmtp_proxy_settings set;
	struct auth_user_info info;
	struct mail_storage_service_input input;
	const char *args, *const *fields, *orig_address = address;
	pool_t pool;
	int ret;

	memset(&input, 0, sizeof(input));
	input.module = input.service = "lmtp";
	mail_storage_service_init_settings(storage_service, &input);

	memset(&info, 0, sizeof(info));
	info.service = master_service_get_name(master_service);
	info.local_ip = client->local_ip;
	info.remote_ip = client->remote_ip;
	info.local_port = client->local_port;
	info.remote_port = client->remote_port;

	pool = pool_alloconly_create("auth lookup", 1024);
	auth_conn = mail_storage_service_get_auth_conn(storage_service);
	ret = auth_master_pass_lookup(auth_conn, address, &info,
				      pool, &fields);
	if (ret <= 0) {
		pool_unref(&pool);
		if (ret < 0) {
			client_send_line(client, ERRSTR_TEMP_USERDB_FAIL,
					 address);
			return TRUE;
		} else {
			/* user not found from passdb. try userdb also. */
			return FALSE;
		}
	}

	memset(&set, 0, sizeof(set));
	set.port = client->local_port;
	set.protocol = LMTP_CLIENT_PROTOCOL_LMTP;
	set.timeout_msecs = LMTP_PROXY_DEFAULT_TIMEOUT_MSECS;

	if (!client_proxy_rcpt_parse_fields(&set, fields, &address)) {
		/* not proxying this user */
		pool_unref(&pool);
		return FALSE;
	}
	if (strcmp(address, orig_address) == 0 &&
	    client_proxy_is_ourself(client, &set)) {
		i_error("Proxying to <%s> loops to itself", address);
		client_send_line(client, "554 5.4.6 Proxying loops to itself");
		pool_unref(&pool);
		return FALSE;
	}

	if (client->proxy == NULL) {
		client->proxy = lmtp_proxy_init(client->set->hostname,
						client->output);
		if (client->mail_body_8bitmime)
			args = " BODY=8BITMIME";
		else if (client->mail_body_7bit)
			args = " BODY=7BIT";
		else
			args = "";
		lmtp_proxy_mail_from(client->proxy, t_strdup_printf(
			"<%s>%s", client->state.mail_from, args));
	}
	if (lmtp_proxy_add_rcpt(client->proxy, address, &set) < 0)
		client_send_line(client, ERRSTR_TEMP_REMOTE_FAILURE);
	else
		client_send_line(client, "250 2.1.5 OK");
	pool_unref(&pool);
	return TRUE;
}

static const char *lmtp_unescape_address(const char *name)
{
	string_t *str;
	const char *p;

	if (*name != '"')
		return name;

	/* quoted-string local-part. drop the quotes unless there's a
	   '@' character inside or there's an error. */
	str = t_str_new(128);
	for (p = name+1; *p != '"'; p++) {
		if (*p == '\0')
			return name;
		if (*p == '\\') {
			if (p[1] == '\0') {
				/* error */
				return name;
			}
			p++;
		}
		if (*p == '@')
			return name;
		str_append_c(str, *p);
	}
	p++;
	if (*p != '@' && *p != '\0')
		return name;

	str_append(str, p);
	return str_c(str);
}

int cmd_rcpt(struct client *client, const char *args)
{
	struct mail_recipient rcpt;
	struct mail_storage_service_input input;
	const char *name, *error = NULL, *addr, *const *argv;
	unsigned int len;
	int ret = 0;

	if (client->state.mail_from == NULL) {
		client_send_line(client, "503 5.5.1 MAIL needed first");
		return 0;
	}

	argv = t_strsplit(args, " ");
	if (argv == NULL)
		addr = "";
	else {
		addr = argv[0];
		argv++;
	}
	len = strlen(addr);
	if (strncasecmp(addr, "TO:<", 4) != 0 || addr[len-1] != '>') {
		client_send_line(client, "501 5.5.4 Invalid parameters");
		return 0;
	}

	memset(&rcpt, 0, sizeof(rcpt));
	name = lmtp_unescape_address(t_strndup(addr + 4, len - 5));

	if (rcpt_is_duplicate(client, name)) {
		client_send_line(client, "250 2.1.5 OK, ignoring duplicate");
		return 0;
	}

	if (*argv != NULL) {
		client_send_line(client, "501 5.5.4 Unsupported options");
		return 0;
	}

	if (client->lmtp_set->lmtp_proxy) {
		if (client_proxy_rcpt(client, name))
			return 0;
	}

	memset(&input, 0, sizeof(input));
	input.service = "lmtp";
	input.module = "lda";
	input.username = name;
	input.local_ip = client->local_ip;
	input.remote_ip = client->remote_ip;

	ret = mail_storage_service_lookup(storage_service, &input,
					  &rcpt.service_user, &error);

	if (ret < 0) {
		i_error("User lookup failed: %s", error);
		client_send_line(client, ERRSTR_TEMP_USERDB_FAIL, name);
		return 0;
	}
	if (ret == 0) {
		client_send_line(client,
				 "550 5.1.1 <%s> User doesn't exist", name);
		return 0;
	}

	rcpt.name = p_strdup(client->state_pool, name);
	array_append(&client->state.rcpt_to, &rcpt, 1);

	client_send_line(client, "250 2.1.5 OK");
	return 0;
}

int cmd_quit(struct client *client, const char *args ATTR_UNUSED)
{
	client_destroy(client, "221 2.0.0", "Client quit");
	return -1;
}

int cmd_vrfy(struct client *client, const char *args ATTR_UNUSED)
{
	client_send_line(client, "252 2.3.3 Try RCPT instead");
	return 0;
}

int cmd_rset(struct client *client, const char *args ATTR_UNUSED)
{
	client_state_reset(client);
	client_send_line(client, "250 2.0.0 OK");
	return 0;
}

int cmd_noop(struct client *client, const char *args ATTR_UNUSED)
{
	client_send_line(client, "250 2.0.0 OK");
	return 0;
}

static int
client_deliver(struct client *client, const struct mail_recipient *rcpt,
	       struct mail *src_mail)
{
	struct mail_deliver_context dctx;
	struct mail_storage *storage;
	void **sets;
	const char *error;
	enum mail_error mail_error;
	int ret;

	i_set_failure_prefix(t_strdup_printf("lmtp(%s, %s): ",
					     my_pid, rcpt->name));
	if (mail_storage_service_next(storage_service, rcpt->service_user,
				      &client->state.dest_user,
				      &error) < 0) {
		i_error("%s", error);
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL, rcpt->name);
		return -1;
	}
	sets = mail_storage_service_user_get_set(rcpt->service_user);

	memset(&dctx, 0, sizeof(dctx));
	dctx.pool = pool_alloconly_create("mail delivery", 1024);
	dctx.set = sets[1];
	dctx.session_id = client->state.session_id;
	dctx.src_mail = src_mail;
	dctx.src_envelope_sender = client->state.mail_from;
	dctx.dest_user = client->state.dest_user;
	dctx.dest_addr = rcpt->name;
	dctx.dest_mailbox_name = "INBOX";
	dctx.save_dest_mail = array_count(&client->state.rcpt_to) > 1 &&
		client->state.first_saved_mail == NULL;

	if (mail_deliver(&dctx, &storage) == 0) {
		if (dctx.dest_mail != NULL) {
			i_assert(client->state.first_saved_mail == NULL);
			client->state.first_saved_mail = dctx.dest_mail;
		}
		client_send_line(client, "250 2.0.0 <%s> %s Saved",
				 rcpt->name, client->state.session_id);
		ret = 0;
	} else if (storage == NULL) {
		/* This shouldn't happen */
		i_error("BUG: Saving failed to unknown storage");
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL,
				 rcpt->name);
		ret = -1;
	} else {
		error = mail_storage_get_last_error(storage, &mail_error);
		if (mail_error == MAIL_ERROR_NOSPACE) {
			client_send_line(client, "%s <%s> %s",
					 dctx.set->quota_full_tempfail ?
					 "452 4.2.2" : "552 5.2.2",
					 rcpt->name, error);
		} else {
			client_send_line(client, "451 4.2.0 <%s> %s",
					 rcpt->name, error);
		}
		ret = -1;
	}
	pool_unref(&dctx.pool);
	return ret;
}

static bool client_deliver_next(struct client *client, struct mail *src_mail)
{
	const struct mail_recipient *rcpts;
	unsigned int count;
	int ret;

	rcpts = array_get(&client->state.rcpt_to, &count);
	while (client->state.rcpt_idx < count) {
		ret = client_deliver(client, &rcpts[client->state.rcpt_idx],
				     src_mail);
		i_set_failure_prefix(t_strdup_printf("lmtp(%s): ", my_pid));

		client->state.rcpt_idx++;
		if (ret == 0)
			return TRUE;
		/* failed. try the next one. */
		if (client->state.dest_user != NULL)
			mail_user_unref(&client->state.dest_user);
	}
	return FALSE;
}

static void client_rcpt_fail_all(struct client *client)
{
	const struct mail_recipient *rcpt;

	array_foreach(&client->state.rcpt_to, rcpt)
		client_send_line(client, ERRSTR_TEMP_MAILBOX_FAIL, rcpt->name);
}

static struct istream *client_get_input(struct client *client)
{
	struct client_state *state = &client->state;
	struct istream *cinput, *inputs[3];

	inputs[0] = i_stream_create_from_data(state->received_line,
					      strlen(state->received_line));

	if (state->mail_data_output != NULL) {
		o_stream_unref(&state->mail_data_output);
		inputs[1] = i_stream_create_fd(state->mail_data_fd,
					       MAIL_READ_FULL_BLOCK_SIZE,
					       FALSE);
		i_stream_set_init_buffer_size(inputs[1],
					      MAIL_READ_FULL_BLOCK_SIZE);
	} else {
		inputs[1] = i_stream_create_from_data(state->mail_data->data,
						      state->mail_data->used);
	}
	inputs[2] = NULL;

	cinput = i_stream_create_concat(inputs);
	i_stream_unref(&inputs[0]);
	i_stream_unref(&inputs[1]);
	return cinput;
}

static int client_open_raw_mail(struct client *client, struct istream *input)
{
	static const char *wanted_headers[] = {
		"From", "To", "Message-ID", "Subject", "Return-Path",
		NULL
	};
	struct mailbox *box;
	struct raw_mailbox *raw_box;
	struct mailbox_header_lookup_ctx *headers_ctx;
	enum mail_error error;

	client->state.raw_box = box =
		mailbox_alloc(client->raw_mail_user->namespaces->list,
			      "Dovecot Delivery Mail", input,
			      MAILBOX_FLAG_NO_INDEX_FILES);
	if (mailbox_open(box) < 0 ||
	    mailbox_sync(box, 0, 0, NULL) < 0) {
		i_error("Can't open delivery mail as raw: %s",
			mail_storage_get_last_error(box->storage, &error));
		mailbox_close(&box);
		client_rcpt_fail_all(client);
		return -1;
	}
	raw_box = (struct raw_mailbox *)box;
	raw_box->envelope_sender = client->state.mail_from;

	client->state.raw_trans = mailbox_transaction_begin(box, 0);

	headers_ctx = mailbox_header_lookup_init(box, wanted_headers);
	client->state.raw_mail = mail_alloc(client->state.raw_trans,
					    0, headers_ctx);
	mailbox_header_lookup_unref(&headers_ctx);
	mail_set_seq(client->state.raw_mail, 1);
	return 0;
}

static void
client_input_data_write_local(struct client *client, struct istream *input)
{
	struct mail *src_mail;

	if (client_open_raw_mail(client, input) < 0)
		return;

	/* save the message to the first recipient's mailbox */
	src_mail = client->state.raw_mail;
	if (!client_deliver_next(client, src_mail))
		return;

	if (client->state.first_saved_mail == NULL)
		mail_user_unref(&client->state.dest_user);
	else
		src_mail = client->state.first_saved_mail;

	/* use the first saved message to save it elsewhere too.
	   this might allow hard linking the files. */
	while (client_deliver_next(client, src_mail))
		mail_user_unref(&client->state.dest_user);

	if (client->state.first_saved_mail != NULL) {
		struct mail *mail = client->state.first_saved_mail;
		struct mailbox_transaction_context *trans = mail->transaction;
		struct mailbox *box = trans->box;
		struct mail_user *user = box->storage->user;

		mail_free(&mail);
		mailbox_transaction_rollback(&trans);
		mailbox_close(&box);
		mail_user_unref(&user);
	}
}

static void client_input_data_finish(struct client *client)
{
	if (client->io != NULL)
		io_remove(&client->io);
	client->io = io_add(client->fd_in, IO_READ, client_input, client);

	client_state_reset(client);
	if (i_stream_have_bytes_left(client->input))
		client_input_handle(client);
}

static void client_proxy_finish(void *context)
{
	struct client *client = context;

	lmtp_proxy_deinit(&client->proxy);
	client_input_data_finish(client);
}

static const char *client_get_received_line(struct client *client)
{
	string_t *str = t_str_new(200);
	const char *host;

	str_printfa(str, "Received: from %s", client->state.lhlo);
	if ((host = net_ip2addr(&client->remote_ip)) != NULL)
		str_printfa(str, " ([%s])", host);
	str_printfa(str, "\r\n\tby %s ("PACKAGE_NAME") with LMTP id %s",
		    client->my_domain, client->state.session_id);

	str_append(str, "\r\n\t");
	if (array_count(&client->state.rcpt_to) == 1) {
		const struct mail_recipient *rcpt =
			array_idx(&client->state.rcpt_to, 0);

		str_printfa(str, "for <%s>", rcpt->name);
	}
	str_printfa(str, "; %s\r\n", message_date_create(ioloop_time));
	return str_c(str);
}

static bool client_input_data_write(struct client *client)
{
	struct istream *input;
	bool ret = TRUE;

	i_stream_destroy(&client->dot_input);

	client->state.received_line =
		p_strdup(client->state_pool, client_get_received_line(client));

	input = client_get_input(client);
	client_input_data_write_local(client, input);
	if (client->proxy != NULL) {
		lmtp_proxy_start(client->proxy, input,
				 client_proxy_finish, client);
		ret = FALSE;
	}
	i_stream_unref(&input);
	return ret;
}

static int client_input_add_file(struct client *client,
				 const unsigned char *data, size_t size)
{
	string_t *path;
	int fd;

	if (client->state.mail_data_output != NULL) {
		/* continue writing to file */
		if (o_stream_send(client->state.mail_data_output,
				  data, size) != (ssize_t)size)
			return -1;
		return 0;
	}

	/* move everything to a temporary file. FIXME: it really shouldn't
	   be in /tmp.. */
	path = t_str_new(256);
	str_append(path, "/tmp/dovecot.lmtp.");
	fd = safe_mkstemp_hostpid(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1)
		return -1;

	/* we just want the fd, unlink it */
	if (unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_error("unlink(%s) failed: %m", str_c(path));
		(void)close(fd);
		return -1;
	}

	client->state.mail_data_fd = fd;
	client->state.mail_data_output = o_stream_create_fd_file(fd, 0, FALSE);
	o_stream_cork(client->state.mail_data_output);
	if (o_stream_send(client->state.mail_data_output,
			  data, size) != (ssize_t)size)
		return -1;
	return 0;
}

static int
client_input_add(struct client *client, const unsigned char *data, size_t size)
{
	if (client->state.mail_data->used + size <=
	    CLIENT_MAIL_DATA_MAX_INMEMORY_SIZE) {
		buffer_append(client->state.mail_data, data, size);
		return 0;
	} else {
		return client_input_add_file(client, data, size);
	}
}

static void client_input_data_handle(struct client *client)
{
	const unsigned char *data;
	size_t size;
	ssize_t ret;

	while ((ret = i_stream_read(client->dot_input)) > 0 || ret == -2) {
		data = i_stream_get_data(client->dot_input, &size);
		if (client_input_add(client, data, size) < 0) {
			client_destroy(client, "451 4.3.0",
				       "Temporary internal failure");
			return;
		}
		i_stream_skip(client->dot_input, size);
	}
	if (ret == 0)
		return;

	if (client_input_data_write(client))
		client_input_data_finish(client);
}

static void client_input_data(struct client *client)
{
	if (client_input_read(client) < 0)
		return;

	client_input_data_handle(client);
}

int cmd_data(struct client *client, const char *args ATTR_UNUSED)
{
	if (client->state.mail_from == NULL) {
		client_send_line(client, "503 5.5.1 MAIL needed first");
		return 0;
	}
	if (array_count(&client->state.rcpt_to) == 0 && client->proxy == NULL) {
		client_send_line(client, "554 5.5.1 No valid recipients");
		return 0;
	}

	i_assert(client->state.mail_data == NULL);
	client->state.mail_data = buffer_create_dynamic(default_pool, 1024*64);

	i_assert(client->dot_input == NULL);
	client->dot_input = i_stream_create_dot(client->input, TRUE);
	client_send_line(client, "354 OK");

	io_remove(&client->io);
	if (array_count(&client->state.rcpt_to) == 0) {
		lmtp_proxy_start(client->proxy, client->dot_input,
				 client_proxy_finish, client);
		i_stream_unref(&client->dot_input);
	} else {
		client->io = io_add(client->fd_in, IO_READ,
				    client_input_data, client);
		client_input_data_handle(client);
	}
	return -1;
}
