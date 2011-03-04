/* Copyright (c) 2010-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "restrict-access.h"
#include "master-service.h"

#include <unistd.h>

struct dns_client {
	int fd;
	struct istream *input;
	struct ostream *output;
	struct io *io;
	struct timeout *to;
};

#define MAX_INBUF_SIZE 1024
#define MAX_OUTBUF_SIZE (1024*64)
#define INPUT_TIMEOUT_MSECS (1000*10)

static struct dns_client *dns_client = NULL;

static void dns_client_destroy(struct dns_client **client);

static int dns_client_input_line(struct dns_client *client, const char *line)
{
	struct ip_addr *ips;
	unsigned int i, ips_count;
	int ret;

	if (strncmp(line, "IP\t", 3) == 0) {
		ret = net_gethostbyname(line + 3, &ips, &ips_count);
		if (ret == 0 && ips_count == 0) {
			/* shouldn't happen, but fix it anyway.. */
			ret = NO_ADDRESS;
		}
		if (ret != 0) {
			o_stream_send_str(client->output,
				t_strdup_printf("%d\n", ret));
		} else {
			o_stream_send_str(client->output,
				t_strdup_printf("0 %u\n", ips_count));
			for (i = 0; i < ips_count; i++) {
				o_stream_send_str(client->output, t_strconcat(
					net_ip2addr(&ips[i]), "\n", NULL));
			}
		}
	} else if (strcmp(line, "QUIT") == 0) {
		return -1;
	} else {
		o_stream_send_str(client->output, "Unknown command\n");
	}

	if (client->output->overflow)
		return -1;
	return 0;
}

static void dns_client_input(struct dns_client *client)
{
	const char *line;
	int ret = 0;

	o_stream_cork(client->output);
	while ((line = i_stream_read_next_line(client->input)) != NULL) {
		if (dns_client_input_line(client, line) < 0) {
			ret = -1;
			break;
		}
	}
	o_stream_uncork(client->output);
	timeout_reset(client->to);

	if (client->input->eof || client->input->stream_errno != 0 || ret < 0)
		dns_client_destroy(&client);
}

static void dns_client_timeout(struct dns_client *client)
{
	dns_client_destroy(&client);
}

static struct dns_client *dns_client_create(int fd)
{
	struct dns_client *client;

	client = i_new(struct dns_client, 1);
	client->fd = fd;
	client->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	client->output = o_stream_create_fd(fd, MAX_OUTBUF_SIZE, FALSE);
	client->io = io_add(fd, IO_READ, dns_client_input, client);
	client->to = timeout_add(INPUT_TIMEOUT_MSECS, dns_client_timeout,
				 client);
	return client;
}

static void dns_client_destroy(struct dns_client **_client)
{
	struct dns_client *client = *_client;

	*_client = NULL;

	timeout_remove(&client->to);
	io_remove(&client->io);
	i_stream_destroy(&client->input);
	o_stream_destroy(&client->output);
	if (close(client->fd) < 0)
		i_error("close() failed: %m");
	i_free(client);

	dns_client = NULL;
	master_service_client_connection_destroyed(master_service);
}

static void client_connected(struct master_service_connection *conn)
{
	if (dns_client != NULL) {
		i_error("dns-client must be configured with client_limit=1");
		return;
	}

	master_service_client_connection_accept(conn);
	dns_client = dns_client_create(conn->fd);
}

int main(int argc, char *argv[])
{
	master_service = master_service_init("dns-client", 0,
					     &argc, &argv, NULL);
	if (master_getopt(master_service) > 0)
		return FATAL_DEFAULT;

	master_service_init_log(master_service, "dns-client: ");
	restrict_access_by_env(NULL, FALSE);
	restrict_access_allow_coredumps(TRUE);

	master_service_init_finish(master_service);

	master_service_run(master_service, client_connected);
	if (dns_client != NULL)
		dns_client_destroy(&dns_client);

	master_service_deinit(&master_service);
        return 0;
}
