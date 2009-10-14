/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "hash.h"
#include "str.h"
#include "hex-binary.h"
#include "ioloop.h"
#include "ostream.h"
#include "fdpass.h"
#include "fd-close-on-exec.h"
#include "../auth/auth-master-interface.h"
#include "service.h"
#include "service-process.h"
#include "service-auth-source.h"

#include <unistd.h>
#include <sys/stat.h>

#define AUTH_SOURCE_OUTBUF_THROTTLE_THRESHOLD (1024 - 256)
#define AUTH_SERVER_MAX_OUTBUF_SIZE (1024*64)
#define AUTH_BUSY_LOG_INTERVAL 30

static void
service_process_auth_source_input(struct service_process_auth_source *process);

static void
service_process_auth_source_close(struct service_process_auth_source *process)
{
	if (process->auth_output != NULL)
		o_stream_close(process->auth_output);
	if (process->io_auth != NULL)
		io_remove(&process->io_auth);
	if (process->auth_fd != -1) {
		if (close(process->auth_fd) < 0)
			i_error("close(auth_fd) failed: %m");
		process->auth_fd = -1;
	}
}

static int
process_auth_source_output(struct service_process_auth_source *process)
{
	int ret;

	if ((ret = o_stream_flush(process->auth_output)) < 0)
		return -1;

	if (process->io_auth == NULL &&
	    o_stream_get_buffer_used_size(process->auth_output) <
	    AUTH_SOURCE_OUTBUF_THROTTLE_THRESHOLD) {
		/* enable parsing input again */
		o_stream_unset_flush_callback(process->auth_output);
		process->io_auth = io_add(process->auth_fd, IO_READ,
					  service_process_auth_source_input,
					  process);
	}
	return ret;
}

void service_process_auth_source_send_reply(struct service_process_auth_source *process,
					    unsigned int tag,
					    enum master_auth_status status)
{
	struct master_auth_reply reply;

	if (o_stream_get_buffer_used_size(process->auth_output) >=
	    AUTH_SOURCE_OUTBUF_THROTTLE_THRESHOLD) {
		/* not reading our output. stop parsing input until it will. */
		if (process->io_auth != NULL) {
			io_remove(&process->io_auth);

			o_stream_set_flush_callback(process->auth_output,
						    process_auth_source_output,
						    process);
		}
	}

	/* Reply to login process */
	memset(&reply, 0, sizeof(reply));
	reply.tag = tag;
	reply.status = status;

	o_stream_send(process->auth_output, &reply, sizeof(reply));
}

static unsigned int
auth_server_send_request(struct service_process_auth_server *server_process,
			 struct service_process_auth_source *source_process,
			 unsigned int auth_id,
			 const uint8_t cookie[MASTER_AUTH_COOKIE_SIZE])
{
	unsigned int tag = 0;
	string_t *str;

	while (tag == 0)
                tag = ++server_process->auth_tag_counter;

	str = t_str_new(256);
	if (!server_process->auth_version_sent) {
                server_process->auth_version_sent = TRUE;
		str_printfa(str, "VERSION\t%u\t%u\n",
			    AUTH_MASTER_PROTOCOL_MAJOR_VERSION,
			    AUTH_MASTER_PROTOCOL_MINOR_VERSION);
		o_stream_send(server_process->auth_output,
			      str_data(str), str_len(str));
		str_truncate(str, 0);
	}

	str_printfa(str, "REQUEST\t%u\t%s\t%u\t",
		    tag, dec2str(source_process->process.pid), auth_id);
	binary_to_hex_append(str, cookie, MASTER_AUTH_COOKIE_SIZE);
	str_append_c(str, '\n');

	o_stream_send(server_process->auth_output, str_data(str), str_len(str));
	return tag;
}

static int
auth_read_request(struct service_process_auth_source *process,
		  struct master_auth_request *req,
		  unsigned char data[MASTER_AUTH_MAX_DATA_SIZE],
		  int *client_fd_r)
{
	struct service *service = process->process.service;
	struct stat st;
	ssize_t ret;

	*client_fd_r = -1;

	ret = fd_read(process->auth_fd, req, sizeof(*req), client_fd_r);
	if (ret != sizeof(*req)) {
		if (ret == 0) {
			/* disconnected */
		} else if (ret > 0) {
			/* request wasn't fully read */
			service_error(service, "fd_read() partial input (%d/%d)",
				      (int)ret, (int)sizeof(*req));
		} else {
			if (errno == EAGAIN)
				return 0;

			service_error(service, "fd_read() failed: %m");
		}
		return -1;
	}

	if (req->data_size != 0) {
		if (req->data_size > MASTER_AUTH_MAX_DATA_SIZE) {
			service_error(service, "Too large auth data_size sent");
			return -1;
		}
		/* @UNSAFE */
		ret = read(process->auth_fd, data, req->data_size);
		if (ret != (ssize_t)req->data_size) {
			if (ret == 0) {
				/* disconnected */
			} else if (ret > 0) {
				/* request wasn't fully read */
				service_error(service,
					      "Data read partially %d/%u",
					      (int)ret, req->data_size);
			} else {
				service_error(service, "read(data) failed: %m");
			}
			return -1;
		}
	}

	if (*client_fd_r == -1) {
		service_error(service, "Auth request missing a file descriptor");
		return -1;
	}

	if (fstat(*client_fd_r, &st) < 0) {
		service_error(service, "fstat(auth dest fd) failed: %m");
		return -1;
	}
	if (st.st_ino != req->ino) {
		service_error(service, "Auth request inode mismatch: %s != %s",
			      dec2str(st.st_ino), dec2str(req->ino));
		return -1;
	}
	return 1;
}

static void
service_process_auth_source_input(struct service_process_auth_source *process)
{
	struct service *service = process->process.service;
	struct service_process_auth_server *auth_process;
	struct service_process_auth_request *auth_req;
	struct master_auth_request req;
	unsigned char data[MASTER_AUTH_MAX_DATA_SIZE];
	unsigned int tag;
	ssize_t ret;
	int client_fd;

	ret = auth_read_request(process, &req, data, &client_fd);
	if (ret == 0)
		return;
	if (ret < 0) {
		if (client_fd != -1) {
			if (close(client_fd) < 0)
				i_error("login: close(mail client) failed: %m");
		}
		service_process_auth_source_close(process);
		return;
	}
	fd_close_on_exec(client_fd, TRUE);

	/* we have a request. check its validity. */
	auth_process = hash_table_lookup(service_pids, &req.auth_pid);
	if (auth_process == NULL) {
		service_error(service, "authentication request for unknown "
			      "auth server PID %s", dec2str(req.auth_pid));
		service_process_auth_source_send_reply(process, req.tag,
			MASTER_AUTH_STATUS_INTERNAL_ERROR);
		(void)close(client_fd);
		return;
	}

	if (o_stream_get_buffer_used_size(auth_process->auth_output) >=
	    AUTH_SERVER_MAX_OUTBUF_SIZE) {
		if (auth_process->auth_busy_stamp <=
		    ioloop_time - AUTH_BUSY_LOG_INTERVAL) {
			i_warning("service(%s): authentication server PID "
				  "%s too busy",
				  auth_process->process.service->set->name,
				  dec2str(req.auth_pid));
                        auth_process->auth_busy_stamp = ioloop_time;
		}
		service_process_auth_source_send_reply(process, req.tag,
			MASTER_AUTH_STATUS_INTERNAL_ERROR);
		(void)close(client_fd);
		return;
	}

	/* ok, we have a non-busy authentication server.
	   send a request to it. */
	auth_req = i_malloc(sizeof(*auth_req) + req.data_size);
	auth_req->process = process;
	auth_req->process_tag = req.tag;
	auth_req->fd = client_fd;
	auth_req->local_ip = req.local_ip;
	auth_req->remote_ip = req.remote_ip;
	auth_req->data_size = req.data_size;
	memcpy(auth_req->data, data, req.data_size);

	tag = auth_server_send_request(auth_process, process, req.auth_id,
				       req.cookie);

	service_process_ref(&process->process);
	hash_table_insert(auth_process->auth_requests,
			  POINTER_CAST(tag), auth_req);
}

void service_process_auth_source_init(struct service_process *_process, int fd)
{
	struct service_process_auth_source *process =
		(struct service_process_auth_source *)_process;

	i_assert(_process->service->type == SERVICE_TYPE_AUTH_SOURCE);

	process->auth_fd = fd;
	process->io_auth = io_add(process->auth_fd, IO_READ,
				  service_process_auth_source_input, process);
	process->auth_output =
		o_stream_create_fd(fd, (size_t)-1, FALSE);
}

void service_process_auth_source_deinit(struct service_process *_process)
{
	struct service_process_auth_source *process =
		(struct service_process_auth_source *)_process;

	i_assert(_process->service->type == SERVICE_TYPE_AUTH_SOURCE);

	service_process_auth_source_close(process);
}

void service_processes_auth_source_notify(struct service *service,
					  bool all_processes_created)
{
	struct hash_iterate_context *iter;
	void *key, *value;
	enum master_auth_status status;

	i_assert(service->type == SERVICE_TYPE_AUTH_SOURCE);

	status = all_processes_created ? 1 : 0;

	iter = hash_table_iterate_init(service_pids);
	while (hash_table_iterate(iter, &key, &value)) {
		struct service_process *process = value;
		struct service_process_auth_source *auth_process;

		if (process->service != service)
			continue;

		auth_process = (struct service_process_auth_source *)process;
		if (auth_process->last_notify_status != (int)status) {
			auth_process->last_notify_status = (int)status;
			service_process_auth_source_send_reply(auth_process,
							       0, status);
		}
	}
	hash_table_iterate_deinit(&iter);
}
