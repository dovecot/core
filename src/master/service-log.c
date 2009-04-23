/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "fd-close-on-exec.h"
#include "array.h"
#include "service.h"
#include "service-log.h"

#include <unistd.h>

int services_log_init(struct service_list *service_list)
{
	struct log_service_handshake handshake;
	struct service *const *services;
	unsigned int i, count;
	buffer_t *handshake_buf;
	ssize_t ret = 0;

	memset(&handshake, 0, sizeof(handshake));
	handshake.log_magic = MASTER_LOG_MAGIC;

	handshake_buf = buffer_create_dynamic(default_pool, 256);
	services = array_get(&service_list->services, &count);
	for (i = 0; i < count; i++) {
		if (services[i]->type == SERVICE_TYPE_LOG)
			continue;

		i_assert(services[i]->log_fd[0] == -1);
		if (pipe(services[i]->log_fd) < 0) {
			i_error("pipe() failed: %m");
			ret = -1;
			break;
		}
		fd_close_on_exec(services[i]->log_fd[0], TRUE);
		fd_close_on_exec(services[i]->log_fd[1], TRUE);

		handshake.prefix_len = strlen(services[i]->name) + 2;

		buffer_set_used_size(handshake_buf, 0);
		buffer_append(handshake_buf, &handshake, sizeof(handshake));
		buffer_append(handshake_buf, services[i]->name,
			      strlen(services[i]->name));
		buffer_append(handshake_buf, ": ", 2);

		ret = write(services[i]->log_fd[1],
			    handshake_buf->data, handshake_buf->used);
		if (ret < 0) {
			i_error("write(log handshake) failed: %m");
			break;
		}
		if ((size_t)ret != handshake_buf->used) {
			i_error("write(log handshake) didn't write everything");
			ret = -1;
			break;
		}
	}
	buffer_free(&handshake_buf);
	if (ret < 0) {
		services_log_deinit(service_list);
		return -1;
	}
	return 0;
}

void services_log_deinit(struct service_list *service_list)
{
	struct service *const *services;
	unsigned int i, count;

	services = array_get(&service_list->services, &count);
	for (i = 0; i < count; i++) {
		if (services[i]->log_fd[0] != -1) {
			if (close(services[i]->log_fd[0]) < 0) {
				i_error("service(%s): close(log_fd) failed: %m",
					services[i]->name);
			}
			if (close(services[i]->log_fd[1]) < 0) {
				i_error("service(%s): close(log_fd) failed: %m",
					services[i]->name);
			}
			services[i]->log_fd[0] = -1;
			services[i]->log_fd[1] = -1;
		}
	}
}

void services_log_dup2(ARRAY_TYPE(dup2) *dups,
		       struct service_list *service_list,
		       unsigned int first_fd, unsigned int *fd_count)
{
	struct service *const *services;
	unsigned int i, n, count;

	services = array_get(&service_list->services, &count);
	for (i = n = 0; i < count; i++) {
		if (services[i]->log_fd[1] != -1) {
			dup2_append(dups, services[i]->log_fd[0], first_fd + n);
			n++; *fd_count += 1;
		}
	}
}
