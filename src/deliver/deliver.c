/* Copyright (C) 2005 Timo Sirainen */

/* FIXME: pretty ugly thing. */

#include "lib.h"
#include "lib-signals.h"
#include "ioloop.h"
#include "env-util.h"
#include "network.h"
#include "restrict-access.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "var-expand.h"
#include "mail-storage.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <sysexits.h>

#define DEFAULT_CONFIG_FILE SYSCONFDIR"/dovecot-deliver.conf"
#define DEFAULT_AUTH_SOCKET_PATH "/var/run/dovecot/auth-master"

#define MAX_INBUF_SIZE 8192
#define MAX_OUTBUF_SIZE 512

struct auth_connection {
	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	unsigned int handshaked:1;
};

static struct ioloop *ioloop;
static int return_value = EX_SOFTWARE;

static void sig_quit(int signo __attr_unused__)
{
	io_loop_stop(ioloop);
}

static int sync_quick(struct mailbox *box)
{
	struct mailbox_sync_context *ctx;
        struct mailbox_sync_rec sync_rec;
	struct mailbox_status status;

	ctx = mailbox_sync_init(box, 0);
	while (mailbox_sync_next(ctx, &sync_rec) > 0)
		;
	return mailbox_sync_deinit(ctx, &status);
}

struct save_mail_context {
	struct mail_save_context *save_ctx;
	struct istream *input;
	int ret;
};

static void save_mail_input(void *context)
{
	struct save_mail_context *ctx = context;

	if (ctx->input->closed ||
	    mailbox_save_continue(ctx->save_ctx) < 0)
		io_loop_stop(ioloop);
	else if (ctx->input->eof) {
		ctx->ret = 0;
		io_loop_stop(ioloop);
	}
}

static int save_mail(struct mail_storage *storage, const char *mailbox,
		     struct istream *input)
{
	struct mailbox *box;
	struct mailbox_transaction_context *t;
        struct save_mail_context ctx;
	struct io *io;
	int ret = 0;

	box = mailbox_open(storage, mailbox, MAILBOX_OPEN_FAST |
			   MAILBOX_OPEN_KEEP_RECENT);
	if (box == NULL)
		return FALSE;

	if (sync_quick(box) < 0) {
		mailbox_close(box);
		return FALSE;
	}

	t = mailbox_transaction_begin(box, FALSE);

	memset(&ctx, 0, sizeof(ctx));
	ctx.ret = -1;
	ctx.input = input;
	ctx.save_ctx = mailbox_save_init(t, 0, NULL, (time_t)-1, 0, NULL,
					 input, FALSE);

	io = io_add(i_stream_get_fd(input), IO_READ, save_mail_input, &ctx);
	io_loop_run(ioloop);
	io_remove(io);

	ret = ctx.ret;
	if (ret < 0)
		mailbox_save_cancel(ctx.save_ctx);
	else
		ret = mailbox_save_finish(ctx.save_ctx, NULL);

	if (ret < 0)
		mailbox_transaction_rollback(t);
	else
		ret = mailbox_transaction_commit(t, 0);

	mailbox_close(box);
	return ret;
}

static void auth_connection_destroy(struct auth_connection *conn)
{
	io_loop_stop(ioloop);

	io_remove(conn->io);
	i_stream_unref(conn->input);
	o_stream_unref(conn->output);
	i_free(conn);
}

static void auth_parse_input(const char *args)
{
	const char *const *tmp;

	for (tmp = t_strsplit(args, "\t"); *tmp != NULL; tmp++) {
		if (strncmp(*tmp, "uid=", 4) == 0) {
			env_put(t_strconcat("RESTRICT_SETUID=",
					    *tmp + 4, NULL));
		} else if (strncmp(*tmp, "gid=", 4) == 0) {
			env_put(t_strconcat("RESTRICT_SETGID=",
					    *tmp + 4, NULL));
		} else if (strncmp(*tmp, "chroot=", 7) == 0) {
			env_put(t_strconcat("RESTRICT_CHROOT=",
					    *tmp + 7, NULL));
		} else if (strncmp(*tmp, "home=", 5) == 0)
			env_put(t_strconcat("HOME=", *tmp + 5, NULL));
	}

	restrict_access_by_env(TRUE);
	return_value = EX_OK;
}

static void auth_input(void *context)
{
	struct auth_connection *conn = context;
	const char *line;

	switch (i_stream_read(conn->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_connection_destroy(conn);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth master sent us more than %d bytes",
			MAX_INBUF_SIZE);
		auth_connection_destroy(conn);
		return;
	}

	if (!conn->handshaked) {
		while ((line = i_stream_next_line(conn->input)) != NULL) {
			if (strncmp(line, "VERSION\t", 8) == 0) {
				if (strncmp(line + 8, "1\t", 2) != 0) {
					i_error("Auth master version mismatch");
					auth_connection_destroy(conn);
					return;
				}
			} else if (strncmp(line, "SPID\t", 5) == 0) {
				conn->handshaked = TRUE;
				break;
			}
		}
	}

	line = i_stream_next_line(conn->input);
	if (line != NULL) {
		if (strncmp(line, "USER\t1\t", 7) == 0) {
			auth_parse_input(line + 7);
		} else if (strcmp(line, "NOTFOUND\t1") == 0)
			return_value = EX_NOUSER;
		else if (strncmp(line, "FAIL\t1\t", 7) == 0)
			return_value = EX_TEMPFAIL;
		else {
			i_error("BUG: Unexpected input from auth master: %s",
				line);
		}
		auth_connection_destroy(conn);
	}
}

static struct auth_connection *auth_connection_new(const char *auth_socket)
{
	struct auth_connection *conn;
	int fd;

	fd = net_connect_unix(auth_socket);
	if (fd < 0) {
		i_error("net_connect(%s) failed: %m", auth_socket);
		return NULL;
	}

	conn = i_new(struct auth_connection, 1);
	conn->fd = fd;
	conn->input =
		i_stream_create_file(fd, default_pool, MAX_INBUF_SIZE, FALSE);
	conn->output =
		o_stream_create_file(fd, default_pool, MAX_OUTBUF_SIZE, FALSE);
	conn->io = io_add(fd, IO_READ, auth_input, conn);
	return conn;
}

static int user_init(const char *auth_socket, const char *destination)
{
        struct auth_connection *conn;

	conn = auth_connection_new(auth_socket);
	if (conn == NULL)
		return EX_TEMPFAIL;

	o_stream_send_str(conn->output,
			  t_strconcat("VERSION\t1\t0\nUSER\t1\t",
				      destination, "\n", NULL));

	io_loop_run(ioloop);
	return return_value;
}

static void config_file_init(const char *path)
{
	struct istream *input;
	const char *line, *p, *key, *value;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		i_fatal_status(EX_CONFIG, "open(%s) failed: %m", path);

	t_push();
	input = i_stream_create_file(fd, default_pool, 1024, TRUE);
	while ((line = i_stream_read_next_line(input)) != NULL) {
		while (*line == ' ') line++;
		if (*line == '#')
			continue;

		value = p = strchr(line, '=');
		if (value == NULL)
			continue;

		while (p > line && p[-1] == ' ') p--;
		key = t_strdup_until(line, p);

		do {
			value++;
		} while (*value == ' ');

		env_put(t_strconcat(t_str_ucase(key), "=", value, NULL));
	}
	i_stream_unref(input);
	t_pop();
}

static const struct var_expand_table *
get_var_expand_table(const char *user, const char *home)
{
	static struct var_expand_table static_tab[] = {
		{ 'u', NULL },
		{ 'n', NULL },
		{ 'd', NULL },
		{ 's', NULL },
		{ 'h', NULL },
		{ 'l', NULL },
		{ 'r', NULL },
		{ 'p', NULL },
		{ '\0', NULL }
	};
	struct var_expand_table *tab;

	tab = t_malloc(sizeof(static_tab));
	memcpy(tab, static_tab, sizeof(static_tab));

	tab[0].value = user;
	tab[1].value = t_strcut(user, '@');
	tab[2].value = strchr(user, '@');
	if (tab[2].value != NULL) tab[2].value++;
	tab[3].value = "DELIVER";
	tab[4].value = home;
	tab[5].value = NULL;
	tab[6].value = NULL;
	tab[7].value = dec2str(getpid());

	return tab;
}

static const char *
expand_mail_env(const char *env, const struct var_expand_table *table)
{
	string_t *str;
	const char *p;

	str = t_str_new(256);

	/* it's either type:data or just data */
	p = strchr(env, ':');
	if (p != NULL) {
		while (env != p) {
			str_append_c(str, *env);
			env++;
		}

		str_append_c(str, *env++);
	}

	if (env[0] == '~' && env[1] == '/') {
		/* expand home */
		env = t_strconcat("%h", env+1, NULL);
	}

	/* expand %vars */
	var_expand(str, env, table);
	return str_c(str);
}

int main(int argc, char *argv[])
{
	const char *auth_socket = DEFAULT_AUTH_SOCKET_PATH;
	const char *destination, *mail;
        const struct var_expand_table *table;
	struct mail_storage *storage;
	struct istream *input;
	int i, ret;

	lib_init();
	lib_init_signals(sig_quit);
	ioloop = io_loop_create(default_pool);

	destination = NULL;
	for (i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-d") == 0) {
			/* destination user */
			i++;
			if (i == argc) {
				i_fatal_status(EX_USAGE,
					       "Missing destination argument");
			}
			destination = argv[i];
		} else if (strcmp(argv[i], "-a") == 0) {
			/* auth master socket path */
			i++;
			if (i == argc) {
				i_fatal_status(EX_USAGE,
					"Missing auth socket path argument");
			}
			auth_socket = argv[i];
		} else {
			i_fatal_status(EX_USAGE,
				       "Unknown argument: %s", argv[1]);
		}
	}

	config_file_init(DEFAULT_CONFIG_FILE);

	if (destination != NULL) {
		ret = user_init(auth_socket, destination);
		if (ret != 0)
			return ret;
	} else if (geteuid() != 0) {
		/* we're non-root. get our username. */
		struct passwd *pw;

		pw = getpwuid(geteuid());
		if (pw != NULL)
			destination = t_strdup(pw->pw_name);
	} 

	if (destination == NULL) {
		i_fatal_status(EX_USAGE,
			"destination user parameter (-d user) not given");
	}

        mail_storage_init();
	mail_storage_register_all();

	mail = getenv("MAIL");
	if (mail == NULL)
		i_fatal_status(EX_CONFIG, "mail setting not given");

        table = get_var_expand_table(destination, getenv("HOME"));
	mail = expand_mail_env(mail, table);

	/* FIXME: how should we handle namespaces? */
	storage = mail_storage_create_with_data(mail, destination, 0);
	if (storage == NULL) {
		i_fatal_status(EX_CONFIG,
			"Failed to create storage for '%s' with mail '%s'",
			destination, mail == NULL ? "(null)" : mail);
	}

	net_set_nonblock(0, TRUE);
	input = i_stream_create_file(0, default_pool, 8192, FALSE);
	if (!save_mail(storage, "INBOX", input))
		return EX_TEMPFAIL;
	i_stream_unref(input);

        mail_storage_destroy(storage);
        mail_storage_deinit();
	io_loop_destroy(ioloop);
	lib_deinit();

        return EX_OK;
}
