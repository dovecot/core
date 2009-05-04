/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "hash.h"
#include "service.h"
#include "service-process.h"
#include "service-auth-server.h"
#include "service-auth-source.h"
#include "../auth/auth-master-interface.h"

#include <stdlib.h>
#include <unistd.h>

#define AUTH_MAX_INBUF_SIZE 8192

static void
service_process_auth_request_free(struct service_process_auth_request *request)
{
	if (request->fd != -1) {
		if (close(request->fd) < 0)
			i_error("close(auth request fd) failed: %m");
	}
	i_free(request);
}

static void
service_process_auth_server_close(struct service_process_auth_server *process)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	if (process->auth_requests != NULL) {
		iter = hash_table_iterate_init(process->auth_requests);
		while (hash_table_iterate(iter, &key, &value)) {
			struct service_process_auth_request *request = value;

			service_process_unref(&request->process->process);
			service_process_auth_request_free(request);
		}
		hash_table_iterate_deinit(&iter);
		hash_table_destroy(&process->auth_requests);
	}

	if (process->auth_input != NULL)
		i_stream_close(process->auth_input);
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

static struct service_process_auth_request *
auth_process_lookup_request(struct service_process_auth_server *process,
			    unsigned int id)
{
        struct service_process_auth_request *request;

	request = hash_table_lookup(process->auth_requests, POINTER_CAST(id));
	if (request == NULL) {
		service_error(process->process.service,
			      "authentication service %s "
			      "sent reply with unknown ID %u",
			      dec2str(process->process.pid), id);
		return NULL;
	}

	hash_table_remove(process->auth_requests, POINTER_CAST(id));
	if (!service_process_unref(&request->process->process)) {
		/* process already died. */
		service_process_auth_request_free(request);
		return NULL;
	}

	return request;
}

static int
auth_process_input_user(struct service_process_auth_server *process, const char *args)
{
        struct service_process_auth_request *request;
	const char *const *list;
	enum master_auth_status status;
	unsigned int id;

	/* <id> <userid> [..] */

	list = t_strsplit(args, "\t");
	if (list[0] == NULL || list[1] == NULL) {
		i_error("BUG: Auth process %s sent corrupted USER line",
			dec2str(process->process.pid));
		return FALSE;
	}
	id = (unsigned int)strtoul(list[0], NULL, 10);

        request = auth_process_lookup_request(process, id);
	if (request != NULL) {
		struct service *dest_service =
			request->process->process.service->auth_dest_service;
		struct service_process *dest_process;

		/* FIXME: handle MASTER_AUTH_STATUS_MAX_CONNECTIONS */
		dest_process = service_process_create(dest_service, list + 1,
						      request->fd,
						      request->data,
						      request->data_size);
		status = dest_process != NULL ?
			MASTER_AUTH_STATUS_OK :
			MASTER_AUTH_STATUS_INTERNAL_ERROR;
		service_process_auth_source_send_reply(request->process,
						       request->process_tag,
						       status);
		service_process_auth_request_free(request);
	}
	return TRUE;
}

static int
auth_process_input_notfound(struct service_process_auth_server *process,
			    const char *args)
{
        struct service_process_auth_request *request;
	unsigned int id;

	id = (unsigned int)strtoul(args, NULL, 10);

        request = auth_process_lookup_request(process, id);
	if (request != NULL) {
		service_process_auth_source_send_reply(request->process,
						       request->process_tag,
						       FALSE);
		service_process_auth_request_free(request);
	}
	return TRUE;
}

static int
auth_process_input_fail(struct service_process_auth_server *process,
			const char *args)
{
        struct service_process_auth_request *request;
 	const char *error;
	unsigned int id;

	error = strchr(args, '\t');
	if (error != NULL)
		error++;

	id = (unsigned int)strtoul(args, NULL, 10);

        request = auth_process_lookup_request(process, id);
	if (request != NULL) {
		service_process_auth_source_send_reply(request->process,
						       request->process_tag,
						       FALSE);
		service_process_auth_request_free(request);
	}
	return TRUE;
}

static void
service_process_auth_server_input(struct service_process_auth_server *process)
{
	const char *line;
	int ret;

	switch (i_stream_read(process->auth_input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		service_process_auth_server_close(process);
		return;
	case -2:
		/* buffer full */
		service_error(process->process.service,
			      "authentication server process %s "
			      "sent us too long line",
			      dec2str(process->process.pid));
		service_process_auth_server_close(process);
		return;
	}

	if (!process->auth_version_received) {
		line = i_stream_next_line(process->auth_input);
		if (line == NULL)
			return;

		/* make sure the major version matches */
		if (strncmp(line, "VERSION\t", 8) != 0 ||
		    atoi(t_strcut(line + 8, '\t')) !=
		    AUTH_MASTER_PROTOCOL_MAJOR_VERSION) {
			service_error(process->process.service,
				      "authentication server process %s "
				      "not compatible with master process "
				      "(mixed old and new binaries?)",
				      dec2str(process->process.pid));
			service_process_auth_server_close(process);
			return;
		}
		process->auth_version_received = TRUE;
	}

	while ((line = i_stream_next_line(process->auth_input)) != NULL) {
		if (strncmp(line, "USER\t", 5) == 0)
			ret = auth_process_input_user(process, line + 5);
		else if (strncmp(line, "NOTFOUND\t", 9) == 0)
			ret = auth_process_input_notfound(process, line + 9);
		else if (strncmp(line, "FAIL\t", 5) == 0)
			ret = auth_process_input_fail(process, line + 5);
		else
			ret = TRUE;

		if (!ret) {
			service_process_auth_server_close(process);
			break;
		}
	}
}

void service_process_auth_server_init(struct service_process *_process, int fd)
{
	struct service_process_auth_server *process =
		(struct service_process_auth_server *)_process;

	i_assert(_process->service->type == SERVICE_TYPE_AUTH_SERVER);

	process->auth_fd = fd;
	process->auth_input = i_stream_create_fd(process->auth_fd,
						 AUTH_MAX_INBUF_SIZE, FALSE);
	process->auth_output =
		o_stream_create_fd(fd, (size_t)-1, FALSE);
	process->io_auth =
		io_add(process->auth_fd, IO_READ,
		       service_process_auth_server_input, process);
	process->auth_requests =
		hash_table_create(default_pool, default_pool, 0, NULL, NULL);
}

void service_process_auth_server_deinit(struct service_process *_process)
{
	struct service_process_auth_server *process =
		(struct service_process_auth_server *)_process;

	i_assert(_process->service->type == SERVICE_TYPE_AUTH_SERVER);

	service_process_auth_server_close(process);
}
