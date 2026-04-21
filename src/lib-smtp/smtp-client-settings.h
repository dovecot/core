#ifndef SMTP_CLIENT_SETTINGS_H
#define SMTP_CLIENT_SETTINGS_H

#define SMTP_DEFAULT_CONNECT_TIMEOUT_MSECS (1000*30)
#define SMTP_DEFAULT_COMMAND_TIMEOUT_MSECS (1000*60*5)
#define SMTP_DEFAULT_MAX_REPLY_SIZE (SIZE_MAX)
#define SMTP_DEFAULT_MAX_DATA_CHUNK_SIZE NET_BLOCK_SIZE
#define SMTP_DEFAULT_MAX_DATA_CHUNK_PIPELINE 4

struct smtp_client_settings {
	struct ip_addr my_ip;
	const char *my_hostname;

	const char *rawlog_dir;

	/* Timeout for SMTP commands. Reset every time more data is being
	   sent or received.
	   (default = 5 minutes) */
	unsigned int command_timeout_msecs;
	/* Timeout for connecting (DNS lookup, TCP connect, TLS handshake).
	   (default = 30 seconds) */
	unsigned int connect_timeout_msecs;

	/* Max total size of reply */
	size_t max_reply_size;

	/* Maximum BDAT chunk size for the CHUNKING capability */
	uoff_t max_data_chunk_size;
	/* Maximum pipelined BDAT commands */
	unsigned int max_data_chunk_pipeline;

	/* the kernel send/receive buffer sizes used for the connection sockets.
	   Configuring this is mainly useful for the test suite. The kernel
	   defaults are used when these settings are 0. */
	size_t socket_send_buffer_size;
	size_t socket_recv_buffer_size;

	/* peer is trusted, so e.g. attempt sending XCLIENT data */
	bool peer_trusted;
};

#endif
