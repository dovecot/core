/* Copyright (c) 2005-2011 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "aqueue.h"
#include "hash.h"
#include "ioloop.h"
#include "fd-close-on-exec.h"
#include "fd-set-nonblock.h"
#include "service.h"
#include "service-process.h"
#include "service-process-notify.h"
#include "service-anvil.h"
#include "service-log.h"

#include <unistd.h>

static int service_log_fds_init(const char *log_prefix, int log_fd[2],
				buffer_t *handshake_buf)
{
	struct log_service_handshake handshake;
	ssize_t ret;

	i_assert(log_fd[0] == -1);

	if (pipe(log_fd) < 0) {
		i_error("pipe() failed: %m");
		return -1;
	}
	fd_close_on_exec(log_fd[0], TRUE);
	fd_close_on_exec(log_fd[1], TRUE);

	memset(&handshake, 0, sizeof(handshake));
	handshake.log_magic = MASTER_LOG_MAGIC;
	handshake.prefix_len = strlen(log_prefix);

	buffer_set_used_size(handshake_buf, 0);
	buffer_append(handshake_buf, &handshake, sizeof(handshake));
	buffer_append(handshake_buf, log_prefix, strlen(log_prefix));

	ret = write(log_fd[1], handshake_buf->data, handshake_buf->used);
	if (ret < 0) {
		i_error("write(log handshake) failed: %m");
		return -1;
	}
	if ((size_t)ret != handshake_buf->used) {
		i_error("write(log handshake) didn't write everything");
		return -1;
	}
	return 0;
}

static int
service_process_write_log_bye(int fd, struct service_process *process)
{
	const char *data;

	data = t_strdup_printf("%d %s BYE\n",
			       process->service->log_process_internal_fd,
			       dec2str(process->pid));
	if (write(fd, data, strlen(data)) < 0) {
		if (errno != EAGAIN)
			i_error("write(log process) failed: %m");
		return -1;
	}
	return 0;
}

int services_log_init(struct service_list *service_list)
{
	struct service *const *services;
	const char *log_prefix;
	buffer_t *handshake_buf;
	ssize_t ret = 0;
	int fd;

	handshake_buf = buffer_create_dynamic(default_pool, 256);
	if (service_log_fds_init(MASTER_LOG_PREFIX_NAME,
				 service_list->master_log_fd,
				 handshake_buf) < 0)
		ret = -1;
	else
		fd_set_nonblock(service_list->master_log_fd[1], TRUE);

	i_assert(service_list->log_byes == NULL);
	service_list->log_byes =
		service_process_notify_init(service_list->master_log_fd[1],
					    service_process_write_log_bye);

	fd = MASTER_LISTEN_FD_FIRST + 1;
	array_foreach(&service_list->services, services) {
		struct service *service = *services;

		if (service->type == SERVICE_TYPE_LOG)
			continue;

		log_prefix = t_strconcat(service->set->name, ": ", NULL);
		if (service_log_fds_init(log_prefix, service->log_fd,
					 handshake_buf) < 0) {
			ret = -1;
			break;
		}
		service->log_process_internal_fd = fd++;
	}

	buffer_free(&handshake_buf);
	if (ret < 0) {
		services_log_deinit(service_list);
		return -1;
	}

	service_anvil_send_log_fd();
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
				service_error(services[i],
					      "close(log_fd) failed: %m");
			}
			if (close(services[i]->log_fd[1]) < 0) {
				service_error(services[i],
					      "close(log_fd) failed: %m");
			}
			services[i]->log_fd[0] = -1;
			services[i]->log_fd[1] = -1;
			services[i]->log_process_internal_fd = -1;
		}
	}
	if (service_list->log_byes != NULL)
		service_process_notify_deinit(&service_list->log_byes);
	if (service_list->master_log_fd[0] != -1) {
		if (close(service_list->master_log_fd[0]) < 0)
			i_error("close(master log fd) failed: %m");
		if (close(service_list->master_log_fd[1]) < 0)
			i_error("close(master log fd) failed: %m");
		service_list->master_log_fd[0] = -1;
		service_list->master_log_fd[1] = -1;
	}
}

void services_log_dup2(ARRAY_TYPE(dup2) *dups,
		       struct service_list *service_list,
		       unsigned int first_fd, unsigned int *fd_count)
{
	struct service *const *services;
	unsigned int n = 0;

	/* master log fd is always the first one */
	dup2_append(dups, service_list->master_log_fd[0], first_fd);
	n++; *fd_count += 1;

	array_foreach(&service_list->services, services) {
		struct service *service = *services;

		if (service->log_fd[1] == -1)
			continue;

		i_assert((int)(first_fd + n) == service->log_process_internal_fd);
		dup2_append(dups, service->log_fd[0], first_fd + n);
		n++; *fd_count += 1;
	}
}
