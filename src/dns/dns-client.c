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

static struct connection_list *dns_clients = NULL;

static int dns_client_input_args(struct connection *client, const char *const *args)
{
	struct ip_addr *ips, ip;
	const char *name;
	unsigned int i, ips_count;
	int ret;

	if (strcmp(args[0], "QUIT") == 0) {
		return -1;
	} else if (args[1] == NULL) {
		i_error("Got empty request");
		return -1;
	}

	if (strcmp(args[0], "IP") == 0) {
		ret = net_gethostbyname(args[1], &ips, &ips_count);
		if (ret == 0 && ips_count == 0) {
			/* shouldn't happen, but fix it anyway.. */
			ret = EAI_NONAME;
		}
		if (ret != 0) {
			o_stream_nsend_str(client->output,
				t_strdup_printf("%d\n", ret));
		} else {
			o_stream_nsend_str(client->output,
				t_strdup_printf("0 %u\n", ips_count));
			for (i = 0; i < ips_count; i++) {
				const char *ip = net_ip2addr(&ips[i]);
				o_stream_nsend_str(client->output, t_strconcat(
					net_ip2addr(&ips[i]), "\n", NULL));
			}
		}
	} else if (strcmp(args[0], "NAME") == 0) {
		if (net_addr2ip(args[1], &ip) < 0)
			o_stream_nsend_str(client->output, "-1\n");
		else if ((ret = net_gethostbyaddr(&ip, &name)) != 0) {
			o_stream_nsend_str(client->output,
				t_strdup_printf("%d\n", ret));
		} else {
			o_stream_nsend_str(client->output,
				t_strdup_printf("0 %s\n", name));
		}
	} else {
		o_stream_nsend_str(client->output, "Unknown command\n");
	}

	return 1;
}

static void dns_client_destroy(struct connection *client)
{
	connection_deinit(client);
	i_free(client);
	master_service_client_connection_destroyed(master_service);
}

static const struct connection_vfuncs dns_client_vfuncs = {
	.input_args = dns_client_input_args,
	.destroy = dns_client_destroy
};

static const struct connection_settings dns_client_set = {
	.dont_send_version = TRUE,
	.input_max_size = (size_t)-1,
	.output_max_size = (size_t)-1
};

static void client_connected(struct master_service_connection *master_conn)
{
	struct connection *conn = i_new(struct connection, 1);
	master_service_client_connection_accept(master_conn);
	connection_init_server(dns_clients, conn, master_conn->name,
			       master_conn->fd, master_conn->fd);
}

int main(int argc, char *argv[])
{
	master_service = master_service_init("dns-client", 0, &argc, &argv, "");
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
