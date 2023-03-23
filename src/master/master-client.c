/* Copyright (c) 2016-2018 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "str.h"
#include "strescape.h"
#include "ostream.h"
#include "connection.h"
#include "log-error-buffer.h"
#include "service.h"
#include "service-process.h"
#include "service-monitor.h"
#include "master-client.h"

struct master_client {
	struct connection conn;
};

static void
master_client_service_status_output(string_t *str,
				    const struct service *service)
{
	str_append_tabescaped(str, service->set->name);
	str_printfa(str, "\t%u\t%u\t%u\t%u\t%u\t%ld\t%u\t%ld\t%c\t%c\t%c\t%"PRIu64"\n",
		    service->process_count, service->process_avail,
		    service->process_limit, service->client_limit,
		    (service->to_throttle == NULL ?
		     0 : ((service->throttle_msecs + 999) / 1000)),
		    (long)service->exit_failure_last,
		    service->exit_failures_in_sec,
		    (long)service->last_drop_warning,
		    service->listen_pending ? 'y' : 'n',
		    service->listening ? 'y' : 'n',
		    service->doveadm_stop ? 'y' : 'n',
		    service->process_count_total);
}

static int
master_client_service_status(struct master_client *client)
{
	struct service *service;
	string_t *str = t_str_new(128);

	array_foreach_elem(&services->services, service) {
		str_truncate(str, 0);
		master_client_service_status_output(str, service);
		o_stream_nsend(client->conn.output, str_data(str), str_len(str));
	}
	o_stream_nsend_str(client->conn.output, "\n");
	return 1;
}

static void
master_client_process_output(string_t *str,
			     const struct service_process *process)
{
	str_append_tabescaped(str, process->service->set->name);
	str_printfa(str, "\t%lu\t%u\t%u\t%ld\t%ld\t%ld\n",
		    (unsigned long)process->pid, process->available_count,
		    process->total_count, (long)process->idle_start,
		    (long)process->last_status_update,
		    (long)process->last_kill_sent);
}

static void
master_client_process_status_list(struct master_client *client,
				  struct service_process *processes,
				  string_t *str)
{
	struct service_process *p;

	for (p = processes; p != NULL; p = p->next) {
		str_truncate(str, 0);
		master_client_process_output(str, p);
		o_stream_nsend(client->conn.output,
			       str_data(str), str_len(str));
	}
}

static int
master_client_process_status(struct master_client *client,
			     const char *const *args)
{
	struct service *service;
	string_t *str = t_str_new(128);

	array_foreach_elem(&services->services, service) {
		if (args[0] != NULL && !str_array_find(args, service->set->name))
			continue;
		master_client_process_status_list(client,
			service->busy_processes, str);
		master_client_process_status_list(client,
			service->idle_processes_head, str);
	}
	o_stream_nsend_str(client->conn.output, "\n");
	return 1;
}

static int master_client_send_errors(struct master_client *client)
{
	struct log_error_buffer_iter *iter;
	const struct log_error *error;
	string_t *str = t_str_new(256);
	int ret = 0;

	iter = log_error_buffer_iter_init(log_error_buffer);
	while ((error = log_error_buffer_iter_next(iter)) != NULL) {
		str_truncate(str, 0);
		str_printfa(str, "%s\t%"PRIdTIME_T".%06u\t",
			    failure_log_type_names[error->type],
			    error->timestamp.tv_sec,
			    (unsigned int)error->timestamp.tv_usec);
		str_append_tabescaped(str, error->prefix);
		str_append_c(str, '\t');
		str_append_tabescaped(str, error->text);
		str_append_c(str, '\n');
		if (o_stream_send(client->conn.output,
				  str_data(str), str_len(str)) < 0) {
			ret = -1;
			break;
		}
	}
	log_error_buffer_iter_deinit(&iter);
	o_stream_nsend_str(client->conn.output, "\n");
	return ret;
}

static int
master_client_stop(struct master_client *client, const char *const *args)
{
	struct service *service;
	const char *reply = "+\n";

	for (unsigned int i = 0; args[i] != NULL; i++) {
		service = service_lookup(services, args[i]);
		if (service == NULL)
			reply = t_strdup_printf("-Unknown service: %s\n", args[i]);
		else {
			service_monitor_stop_close(service);
			service->doveadm_stop = TRUE;
		}
	}
	o_stream_nsend_str(client->conn.output, reply);
	return 1;
}

static int
master_client_input_args(struct connection *conn, const char *const *args)
{
	struct master_client *client = (struct master_client *)conn;
	const char *cmd = args[0];

	if (cmd == NULL) {
		e_error(conn->event, "Empty command");
		return 0;
	}
	args++;

	if (strcmp(cmd, "SERVICE-STATUS") == 0)
		return master_client_service_status(client);
	if (strcmp(cmd, "PROCESS-STATUS") == 0)
		return master_client_process_status(client, args);
	if (strcmp(cmd, "ERROR-LOG") == 0)
		return master_client_send_errors(client);
	if (strcmp(cmd, "STOP") == 0)
		return master_client_stop(client, args);
	e_error(conn->event, "Unknown command: %s", cmd);
	return -1;
}

static void master_client_destroy(struct connection *conn)
{
	struct master_client *client = (struct master_client *)conn;

	connection_deinit(conn);
	i_free(client);
}

static const struct connection_settings master_conn_set = {
	.service_name_in = "master-client",
	.service_name_out = "master-server",
	.major_version = 1,
	.minor_version = 0,

	.input_max_size = 1024,
	.output_max_size = 1024,
	.client = FALSE
};

static const struct connection_vfuncs master_conn_vfuncs = {
	.destroy = master_client_destroy,
	.input_args = master_client_input_args
};

static struct connection_list *master_connections;

void master_client_connected(struct service_list *service_list)
{
	struct master_client *client;
	int fd;

	fd = net_accept(service_list->master_fd, NULL, NULL);
	if (fd < 0) {
		if (fd == -2)
			e_error(service_list->event, "net_accept() failed: %m");
		return;
	}
	fd_close_on_exec(fd, TRUE);
	client = i_new(struct master_client, 1);
	connection_init_server(master_connections, &client->conn,
			       "master-client", fd, fd);
}

void master_clients_init(void)
{
	master_connections = connection_list_init(&master_conn_set,
						  &master_conn_vfuncs);
}

void master_clients_deinit(void)
{
	connection_list_deinit(&master_connections);
}
