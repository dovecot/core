/* Copyright (c) 2002-2018 Dovecot authors, see the included COPYING file */

#include "lmtp-common.h"
#include "ioloop.h"
#include "path-util.h"
#include "restrict-access.h"
#include "anvil-client.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "master-interface.h"
#include "mail-deliver.h"
#include "mail-storage-service.h"
#include "smtp-submit-settings.h"
#include "lda-settings.h"

#include <unistd.h>

#define DNS_CLIENT_SOCKET_PATH "dns-client"
#define LMTP_MASTER_FIRST_LISTEN_FD 3

#define IS_STANDALONE() \
        (getenv(MASTER_IS_PARENT_ENV) == NULL)

struct smtp_server *lmtp_server = NULL;

char *dns_client_socket_path, *base_dir;
struct mail_storage_service_ctx *storage_service;
struct anvil_client *anvil;

lmtp_client_created_func_t *hook_client_created = NULL;

struct event_category event_category_lmtp = {
	.name = "lmtp",
};

lmtp_client_created_func_t *
lmtp_client_created_hook_set(lmtp_client_created_func_t *new_hook)
{
	lmtp_client_created_func_t *old_hook = hook_client_created;

	hook_client_created = new_hook;
	return old_hook;
}

void lmtp_anvil_init(void)
{
	if (anvil == NULL) {
		const char *path = t_strdup_printf("%s/anvil", base_dir);
		anvil = anvil_client_init(path, NULL, 0);
	}
}

static void client_connected(struct master_service_connection *conn)
{
	master_service_client_connection_accept(conn);
	(void)client_create(conn->fd, conn->fd, conn);
}

static void drop_privileges(void)
{
	struct restrict_access_settings set;
	const char *error;

	/* by default we don't drop any privileges, but keep running as root. */
	restrict_access_get_env(&set);
	/* open config connection before dropping privileges */
	struct master_service_settings_input input;
	struct master_service_settings_output output;

	i_zero(&input);
	input.module = "lmtp";
	input.service = "lmtp";
	if (master_service_settings_read(master_service,
					 &input, &output, &error) < 0)
		i_fatal("Error reading configuration: %s", error);
	restrict_access_by_env(RESTRICT_ACCESS_FLAG_ALLOW_ROOT, NULL);
}

static void main_init(void)
{
	struct master_service_connection conn;
	struct smtp_server_settings lmtp_set;

	i_zero(&lmtp_set);
	lmtp_set.protocol = SMTP_PROTOCOL_LMTP;
	lmtp_set.auth_optional = TRUE;
	lmtp_set.rcpt_domain_optional = TRUE;
	lmtp_set.mail_path_allow_broken = TRUE;

	lmtp_server = smtp_server_init(&lmtp_set);

	if (IS_STANDALONE()) {
		i_zero(&conn);
		(void)client_create(STDIN_FILENO, STDOUT_FILENO, &conn);
	}

	const char *error, *tmp_socket_path;
	if (t_abspath(DNS_CLIENT_SOCKET_PATH, &tmp_socket_path, &error) < 0) {
		i_fatal("t_abspath(%s) failed: %s", DNS_CLIENT_SOCKET_PATH, error);
	}
	dns_client_socket_path = i_strdup(tmp_socket_path);
	mail_deliver_hooks_init();
}

static void main_deinit(void)
{
	clients_destroy();
	if (anvil != NULL)
		anvil_client_deinit(&anvil);
	i_free(dns_client_socket_path);
	i_free(base_dir);
	smtp_server_deinit(&lmtp_server);
}

int main(int argc, char *argv[])
{
	const struct setting_parser_info *set_roots[] = {
		&smtp_submit_setting_parser_info,
		&lda_setting_parser_info,
		&lmtp_setting_parser_info,
		NULL
	};
	enum master_service_flags service_flags =
		MASTER_SERVICE_FLAG_USE_SSL_SETTINGS |
		MASTER_SERVICE_FLAG_HAVE_STARTTLS;
	enum mail_storage_service_flags storage_service_flags =
		MAIL_STORAGE_SERVICE_FLAG_USERDB_LOOKUP |
		MAIL_STORAGE_SERVICE_FLAG_TEMP_PRIV_DROP |
		MAIL_STORAGE_SERVICE_FLAG_NO_LOG_INIT |
		MAIL_STORAGE_SERVICE_FLAG_NO_IDLE_TIMEOUT;
	const char *tmp_base_dir;
	int c;

	if (IS_STANDALONE()) {
		service_flags |= MASTER_SERVICE_FLAG_STANDALONE |
			MASTER_SERVICE_FLAG_STD_CLIENT;
	} else {
		service_flags |= MASTER_SERVICE_FLAG_KEEP_CONFIG_OPEN  ;
	}

	master_service = master_service_init("lmtp", service_flags,
					     &argc, &argv, "D");
	while ((c = master_getopt(master_service)) > 0) {
		switch (c) {
		case 'D':
			storage_service_flags |=
				MAIL_STORAGE_SERVICE_FLAG_ENABLE_CORE_DUMPS;
			break;
		default:
			return FATAL_DEFAULT;
		}
	}

	const char *error;
	if (t_get_working_dir(&tmp_base_dir, &error) < 0)
		i_fatal("Could not get working directory: %s", error);
	base_dir = i_strdup(tmp_base_dir);

	drop_privileges();
	master_service_init_log_with_pid(master_service);

	storage_service = mail_storage_service_init(master_service, set_roots,
						    storage_service_flags);
	restrict_access_allow_coredumps(TRUE);

	main_init();
	master_service_init_finish(master_service);
	master_service_run(master_service, client_connected);

	main_deinit();
	mail_storage_service_deinit(&storage_service);
	master_service_deinit(&master_service);
	return 0;
}
