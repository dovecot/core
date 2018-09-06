/* Copyright (c) 2010-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "istream.h"
#include "ostream.h"
#include "array.h"
#include "strfuncs.h"
#include "connection.h"
#include "restrict-access.h"
#include "master-service.h"

#include <unistd.h>

static struct event_category event_category_dns = {
	.name = "dns-worker"
};

static struct connection_list *dns_clients = NULL;

static int dns_client_input_args(struct connection *client, const char *const *args)
{
	struct ip_addr *ips, ip;
	const char *name;
	struct event *event;
	unsigned int i, ips_count;
	int ret;
	struct event_passthrough *e;

	if (strcmp(args[0], "QUIT") == 0) {
		return -1;
	} else if (args[1] == NULL) {
		e_error(client->event, "Got empty request");
		return -1;
	}

	event = event_create(client->event);
	event_set_append_log_prefix(event, t_strconcat(args[1], ": ", NULL));

	e = event_create_passthrough(event)->
                set_name("dns_worker_request_started")->
                add_str("name", args[1]);
	e_debug(e->event(), "Resolving");

	e = event_create_passthrough(event)->
		set_name("dns_worker_request_finished")->
		add_str("name", args[1]);

	if (strcmp(args[0], "IP") == 0) {
		ret = net_gethostbyname(args[1], &ips, &ips_count);
		if (ret == 0 && ips_count == 0) {
			/* shouldn't happen, but fix it anyway.. */
			ret = EAI_NONAME;
		}
		/* update timestamp after hostname lookup so the event duration
		   field gets set correctly */
		io_loop_time_refresh();
		if (ret != 0) {
			const char *err = net_gethosterror(ret);
			e->add_int("error_code", ret);
			e->add_str("error", err);
			e_debug(e->event(), "Resolve failed: %s", err);
			o_stream_nsend_str(client->output,
				t_strdup_printf("%d\t%s\n", ret, err));
		} else {
			ARRAY_TYPE(const_string) tmp;
			t_array_init(&tmp, ips_count);
			o_stream_nsend_str(client->output, "0\t");
			for (i = 0; i < ips_count; i++) {
				const char *ip = net_ip2addr(&ips[i]);
				array_append(&tmp, &ip, 1);
			}
			array_append_zero(&tmp);
			e_debug(e->event(), "Resolve success: %s",
				t_strarray_join(array_idx(&tmp, 0), ", "));
			o_stream_nsend_str(client->output,
					   t_strarray_join(array_idx(&tmp, 0), "\t"));
			o_stream_nsend_str(client->output, "\n");
		}
	} else if (strcmp(args[0], "NAME") == 0) {
		if (net_addr2ip(args[1], &ip) < 0) {
			e->add_int("error_code", EAI_FAIL);
			e->add_str("error", "Not an IP");
			e_debug(e->event(), "Resolve failed: Not an IP");
			o_stream_nsend_str(client->output, "-1\tNot an IP\n");
		} else if ((ret = net_gethostbyaddr(&ip, &name)) != 0) {
			const char *err = net_gethosterror(ret);
			e->add_int("error_code", ret);
			e->add_str("error", err);
			e_debug(e->event(), "Resolve failed: %s", err);
			o_stream_nsend_str(client->output,
				t_strdup_printf("%d\t%s\n", ret, err));
		} else {
			e_debug(e->event(), "Resolve success: %s", name);
			o_stream_nsend_str(client->output,
				t_strdup_printf("0\t%s\n", name));
		}
	} else {
		e->add_str("error", "Unknown command");
		e_error(e->event(), "Unknown command '%s'", args[0]);
		o_stream_nsend_str(client->output, "-1\tUnknown command\n");
	}

	event_unref(&event);

	return 1;
}

static void dns_client_destroy(struct connection *client)
{
	connection_deinit(client);
	event_unref(&client->event);
	i_free(client);
	master_service_client_connection_destroyed(master_service);
}

static const struct connection_vfuncs dns_client_vfuncs = {
	.input_args = dns_client_input_args,
	.destroy = dns_client_destroy
};

static const struct connection_settings dns_client_set = {
	.service_name_in = "dns-client",
	.service_name_out = "dns",
	.major_version = 1,
	.minor_version = 0,
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1
};

static void client_connected(struct master_service_connection *master_conn)
{
	struct connection *conn = i_new(struct connection, 1);
	master_service_client_connection_accept(master_conn);
	connection_init_server(dns_clients, conn, master_conn->name,
			       master_conn->fd, master_conn->fd);
	event_add_category(conn->event, &event_category_dns);
}

int main(int argc, char *argv[])
{
	master_service = master_service_init("dns-client", 0,
					     &argc, &argv, "");
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	master_service_init_log(master_service, "dns-client: ");
	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
	restrict_access_allow_coredumps(TRUE);

	master_service_init_finish(master_service);

	/* setup connection list */
	dns_clients = connection_list_init(&dns_client_set, &dns_client_vfuncs);

	master_service_run(master_service, client_connected);

	/* disconnect all clients */
	connection_list_deinit(&dns_clients);

	master_service_deinit(&master_service);
        return 0;
}
