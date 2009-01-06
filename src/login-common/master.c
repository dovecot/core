/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "hash.h"
#include "buffer.h"
#include "ioloop.h"
#include "network.h"
#include "fdpass.h"
#include "istream.h"
#include "env-util.h"
#include "write-full.h"
#include "master.h"
#include "client-common.h"

#include <unistd.h>

static int master_fd;
static struct io *io_master;
static struct hash_table *master_requests;
static unsigned int master_tag_counter;

static unsigned int master_pos;
static char master_buf[sizeof(struct master_login_reply)];
static struct client destroyed_client;

static void client_call_master_callback(struct client *client,
					const struct master_login_reply *reply)
{
	master_callback_t *master_callback;

	master_callback = client->master_callback;
	client->master_tag = 0;
	client->master_callback = NULL;

	master_callback(client, reply);
}

static void request_handle(struct master_login_reply *reply)
{
	struct client *client;

	if (reply->tag == 0 && !process_per_connection) {
		/* this means we have to start listening again.
		   we've reached maximum number of login processes. */
		main_listen_start();
		return;
	}

	client = hash_table_lookup(master_requests, POINTER_CAST(reply->tag));
	if (client == NULL)
		i_fatal("Master sent reply with unknown tag %u", reply->tag);

	hash_table_remove(master_requests, POINTER_CAST(reply->tag));
	if (client != &destroyed_client) {
		client_call_master_callback(client, reply);
		/* NOTE: client may be destroyed now */
	}
}

void master_request_login(struct client *client, master_callback_t *callback,
			  unsigned int auth_pid, unsigned int auth_id)
{
	buffer_t *buf;
	struct master_login_request *req;
	struct stat st;
	const unsigned char *data;
	size_t size;
	ssize_t ret;
	unsigned int cmd_tag_size;

	i_assert(auth_pid != 0);

	if (master_fd == -1) {
		struct master_login_reply reply;

		i_assert(closing_down);
		memset(&reply, 0, sizeof(reply));
		reply.status = MASTER_LOGIN_STATUS_INTERNAL_ERROR;
		callback(client, &reply);
		return;
	}

	data = i_stream_get_data(client->input, &size);
	cmd_tag_size = client->auth_command_tag == NULL ? 0 :
		strlen(client->auth_command_tag);

	buf = buffer_create_dynamic(pool_datastack_create(),
				    sizeof(*req) + size + cmd_tag_size);
	buffer_write(buf, sizeof(*req), client->auth_command_tag, cmd_tag_size);
	buffer_write(buf, sizeof(*req) + cmd_tag_size, data, size);
	req = buffer_get_space_unsafe(buf, 0, sizeof(*req));
	req->version = MASTER_LOGIN_PROTOCOL_VERSION;
	req->tag = ++master_tag_counter;
	if (req->tag == 0)
		req->tag = ++master_tag_counter;
	req->auth_pid = auth_pid;
	req->auth_id = auth_id;
	req->local_ip = client->local_ip;
	req->remote_ip = client->ip;
	req->cmd_tag_size =  cmd_tag_size;
	req->data_size = req->cmd_tag_size + size;
#if (LOGIN_MAX_INBUF_SIZE*2) != MASTER_LOGIN_MAX_DATA_SIZE
#  error buffer max sizes unsynced
#endif
	i_assert(req->data_size <= LOGIN_MAX_INBUF_SIZE);

	if (fstat(client->fd, &st) < 0)
		i_fatal("fstat(client) failed: %m");
	req->ino = st.st_ino;

	ret = fd_send(master_fd, client->fd, buf->data, buf->used);
	if (ret < 0)
		i_fatal("fd_send(%d) failed: %m", client->fd);
	if ((size_t)ret != buf->used) {
		i_fatal("fd_send() sent only %d of %d bytes",
			(int)ret, (int)buf->used);
	}

	client->master_tag = req->tag;
	client->master_callback = callback;

	hash_table_insert(master_requests, POINTER_CAST(req->tag), client);
}

void master_request_abort(struct client *client)
{
	struct master_login_reply reply;

	/* we're still going to get the reply from the master, so just
	   remember that we want to ignore it */
	hash_table_update(master_requests, POINTER_CAST(client->master_tag),
			  &destroyed_client);

	memset(&reply, 0, sizeof(reply));
	reply.status = MASTER_LOGIN_STATUS_INTERNAL_ERROR;
	client_call_master_callback(client, &reply);
}

void master_notify_state_change(enum master_login_state state)
{
	struct master_login_request req;

	if (io_master == NULL)
		return;

	memset(&req, 0, sizeof(req));
	req.version = MASTER_LOGIN_PROTOCOL_VERSION;
	req.tag = state;
	req.ino = (ino_t)-1;

	/* sending -1 as fd does the notification */
	if (fd_send(master_fd, -1, &req, sizeof(req)) != sizeof(req))
		i_fatal("fd_send(-1) failed: %m");
}

void master_close(void)
{
	if (io_master == NULL)
		return;

	io_remove(&io_master);
	if (close(master_fd) < 0)
		i_fatal("close(master) failed: %m");
	master_fd = -1;

	closing_down = TRUE;
        main_listen_stop();
	main_unref();

        /* may call this function again through main_unref() */
	clients_destroy_all();
}

static void master_exec(int fd)
{
	static char dovecot[] = "dovecot";
	char *argv[] = { dovecot, NULL };

	switch (fork()) {
	case -1:
		i_fatal("fork() failed: %m");
	case 0:
		if (dup2(fd, 0) < 0)
			i_fatal("master_exec: dup2(%d, 0) failed: %m", fd);
		(void)close(fd);

		if (setsid() < 0)
			i_fatal("setsid() failed: %m");

		env_put("DOVECOT_INETD=1");
		execv(SBINDIR"/dovecot", argv);
		i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m",
			       SBINDIR"/dovecot");
	default:
		(void)close(fd);
	}
}

static void master_read_env(int fd)
{
	struct istream *input;
	const char *line;

	env_clean();

	/* read environment variable lines until empty line comes */
	input = i_stream_create_fd(fd, 8192, FALSE);
	do {
		switch (i_stream_read(input)) {
		case -1:
			i_fatal("EOF while reading environment from master");
		case -2:
			i_fatal("Too large environment line from master");
		}

		while ((line = i_stream_next_line(input)) != NULL &&
		       *line != '\0')
			env_put(line);
	} while (line == NULL);

	i_stream_destroy(&input);
}

int master_connect(const char *group_name)
{
	const char *path = PKG_RUNDIR"/master";
	int i, fd = -1;

	for (i = 0; i < 5 && fd == -1; i++) {
		fd = net_connect_unix(path);
		if (fd != -1)
			break;

		if (errno == ECONNREFUSED) {
			if (unlink(path) < 0)
				i_error("unlink(%s) failed: %m", path);
		} else if (errno != ENOENT) {
			i_fatal("Can't connect to master UNIX socket %s: %m",
				path);
		}

		/* need to create it */
		fd = net_listen_unix(path, 16);
		if (fd != -1) {
			master_exec(fd);
			fd = -1;
		} else if (errno != EADDRINUSE) {
			i_fatal("Can't create master UNIX socket %s: %m", path);
		}
	}

	if (fd == -1)
		i_fatal("Couldn't use/create UNIX socket %s", path);

	if (group_name[0] == '\0')
		i_fatal("No login group name set");

	if (strlen(group_name) >= 256)
		i_fatal("Login group name too large: %s", group_name);

	/* group_name length is now guaranteed to be in range of 1..255 so we
	   can send <length byte><name> */
	group_name = t_strdup_printf("%c%s", (unsigned char)strlen(group_name),
				     group_name);
	if (write_full(fd, group_name, strlen(group_name)) < 0)
		i_fatal("write_full(master_fd) failed: %m");

	master_read_env(fd);
	return fd;
}

static void master_input(void *context ATTR_UNUSED)
{
	int ret;

	ret = net_receive(master_fd, master_buf + master_pos,
			  sizeof(master_buf) - master_pos);
	if (ret < 0) {
		/* master died, kill all clients logging in */
		master_close();
		return;
	}

	master_pos += ret;
	if (master_pos < sizeof(master_buf))
		return;

	/* reply is now read */
	request_handle((void *)master_buf);
	master_pos = 0;
}

void master_init(int fd)
{
	main_ref();

	master_fd = fd;
	master_requests = hash_table_create(system_pool, system_pool,
					    0, NULL, NULL);

        master_pos = 0;
	io_master = io_add(master_fd, IO_READ, master_input, NULL);
}

void master_deinit(void)
{
	hash_table_destroy(&master_requests);

	if (io_master != NULL)
		io_remove(&io_master);
}
