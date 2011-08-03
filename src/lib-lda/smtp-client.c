/* Copyright (c) 2006-2011 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "ioloop.h"
#include "str.h"
#include "close-keep-errno.h"
#include "safe-mkstemp.h"
#include "execv-const.h"
#include "istream.h"
#include "master-service.h"
#include "lmtp-client.h"
#include "lda-settings.h"
#include "mail-deliver.h"
#include "smtp-client.h"

#include <unistd.h>
#include <sys/wait.h>
#include <sysexits.h>

#define DEFAULT_SUBMISSION_PORT 25

struct smtp_client {
	FILE *f;
	pid_t pid;

	bool use_smtp;
	bool success;
	bool finished;

	const struct lda_settings *set;
	char *temp_path;
	char *destination;
	char *return_path;
};

static struct smtp_client *smtp_client_devnull(FILE **file_r)
{
	struct smtp_client *client;

	client = i_new(struct smtp_client, 1);
	client->f = *file_r = fopen("/dev/null", "w");
	if (client->f == NULL)
		i_fatal("fopen() failed: %m");
	client->pid = (pid_t)-1;
	return client;
}

static void ATTR_NORETURN
smtp_client_run_sendmail(const struct lda_settings *set,
			 const char *destination,
			 const char *return_path, int fd)
{
	const char *argv[7], *sendmail_path;

	/* deliver_set's contents may point to environment variables.
	   deliver_env_clean() cleans them up, so they have to be copied. */
	sendmail_path = t_strdup(set->sendmail_path);

	argv[0] = sendmail_path;
	argv[1] = "-i"; /* ignore dots */
	argv[2] = "-f";
	argv[3] = return_path != NULL && *return_path != '\0' ?
		return_path : "<>";
	argv[4] = "--";
	argv[5] = destination;
	argv[6] = NULL;

	if (dup2(fd, STDIN_FILENO) < 0)
		i_fatal("dup2() failed: %m");

	master_service_env_clean();

	execv_const(sendmail_path, argv);
}

static struct smtp_client *
smtp_client_open_sendmail(const struct lda_settings *set,
			  const char *destination, const char *return_path,
			  FILE **file_r)
{
	struct smtp_client *client;
	int fd[2];
	pid_t pid;

	if (pipe(fd) < 0) {
		i_error("pipe() failed: %m");
		return smtp_client_devnull(file_r);
	}

	if ((pid = fork()) == (pid_t)-1) {
		i_error("fork() failed: %m");
		(void)close(fd[0]); (void)close(fd[1]);
		return smtp_client_devnull(file_r);
	}
	if (pid == 0) {
		/* child */
		(void)close(fd[1]);
		smtp_client_run_sendmail(set, destination, return_path, fd[0]);
	}
	(void)close(fd[0]);

	client = i_new(struct smtp_client, 1);
	client->f = *file_r = fdopen(fd[1], "w");
	client->pid = pid;
	if (client->f == NULL)
		i_fatal("fdopen() failed: %m");
	return client;
}

static int create_temp_file(const char **path_r)
{
	string_t *path;
	int fd;

	path = t_str_new(128);
	str_append(path, "/tmp/dovecot.");
	str_append(path, master_service_get_name(master_service));
	str_append_c(path, '.');

	fd = safe_mkstemp(path, 0600, (uid_t)-1, (gid_t)-1);
	if (fd == -1) {
		i_error("safe_mkstemp(%s) failed: %m", str_c(path));
		return -1;
	}

	/* we just want the fd, unlink it */
	if (unlink(str_c(path)) < 0) {
		/* shouldn't happen.. */
		i_error("unlink(%s) failed: %m", str_c(path));
		close_keep_errno(fd);
		return -1;
	}

	*path_r = str_c(path);
	return fd;
}

struct smtp_client *
smtp_client_open(const struct lda_settings *set, const char *destination,
		 const char *return_path, FILE **file_r)
{
	struct smtp_client *client;
	const char *path;
	int fd;

	if (*set->submission_host == '\0') {
		return smtp_client_open_sendmail(set, destination,
						 return_path, file_r);
	}

	if ((fd = create_temp_file(&path)) == -1)
		return smtp_client_devnull(file_r);

	client = i_new(struct smtp_client, 1);
	client->set = set;
	client->temp_path = i_strdup(path);
	client->destination = i_strdup(destination);
	client->return_path = i_strdup(return_path);
	client->f = *file_r = fdopen(fd, "w");
	if (client->f == NULL)
		i_fatal("fdopen() failed: %m");
	client->use_smtp = TRUE;
	return client;
}

static int smtp_client_close_sendmail(struct smtp_client *client)
{
	int ret = EX_TEMPFAIL, status;

	fclose(client->f);

	if (client->pid == (pid_t)-1) {
		/* smtp_client_open() failed already */
	} else if (waitpid(client->pid, &status, 0) < 0)
		i_error("waitpid() failed: %m");
	else if (WIFEXITED(status)) {
		ret = WEXITSTATUS(status);
		if (ret != 0) {
			i_error("Sendmail process terminated abnormally, "
				"exit status %d", ret);
		}
	} else if (WIFSIGNALED(status)) {
		i_error("Sendmail process terminated abnormally, "
				"signal %d", WTERMSIG(status));
	} else if (WIFSTOPPED(status)) {
		i_error("Sendmail process stopped, signal %d",
			WSTOPSIG(status));
	} else {
		i_error("Sendmail process terminated abnormally, "
			"return status %d", status);
	}
	i_free(client);
	return ret;
}

static void smtp_client_send_finished(void *context)
{
	struct smtp_client *smtp_client = context;

	smtp_client->finished = TRUE;
	io_loop_stop(current_ioloop);
}

static void
rcpt_to_callback(bool success, const char *reply, void *context)
{
	struct smtp_client *smtp_client = context;

	if (!success) {
		i_error("smtp(%s): RCPT TO failed: %s",
			smtp_client->set->submission_host, reply);
		smtp_client_send_finished(smtp_client);
	}
}

static void
data_callback(bool success, const char *reply, void *context)
{
	struct smtp_client *smtp_client = context;

	if (!success) {
		i_error("smtp(%s): DATA failed: %s",
			smtp_client->set->submission_host, reply);
		smtp_client_send_finished(smtp_client);
	} else {
		smtp_client->success = TRUE;
	}
}

static int smtp_client_send(struct smtp_client *smtp_client)
{
	struct lmtp_client_settings client_set;
	struct lmtp_client *client;
	struct ioloop *ioloop;
	struct istream *input;
	const char *host, *p;
	unsigned int port = DEFAULT_SUBMISSION_PORT;

	host = smtp_client->set->submission_host;
	p = strchr(host, ':');
	if (p != NULL) {
		host = t_strdup_until(host, p);
		if (str_to_uint(p + 1, &port) < 0 ||
		    port == 0 || port > 65535) {
			i_error("Invalid port in submission_host: %s", p+1);
			return -1;
		}
	}

	if (fflush(smtp_client->f) != 0) {
		i_error("fflush(%s) failed: %m", smtp_client->temp_path);
		return -1;
	}

	if (lseek(fileno(smtp_client->f), 0, SEEK_SET) < 0) {
		i_error("lseek(%s) failed: %m", smtp_client->temp_path);
		return -1;
	}

	memset(&client_set, 0, sizeof(client_set));
	client_set.mail_from = smtp_client->return_path == NULL ? "<>" :
		t_strconcat("<", smtp_client->return_path, ">", NULL);
	client_set.my_hostname = smtp_client->set->hostname;
	client_set.dns_client_socket_path = "dns-client";

	ioloop = io_loop_create();
	client = lmtp_client_init(&client_set, smtp_client_send_finished,
				  smtp_client);

	if (lmtp_client_connect_tcp(client, LMTP_CLIENT_PROTOCOL_SMTP,
				    host, port) < 0) {
		lmtp_client_deinit(&client);
		io_loop_destroy(&ioloop);
		return -1;
	}

	lmtp_client_add_rcpt(client, smtp_client->destination,
			     rcpt_to_callback, data_callback, smtp_client);

	input = i_stream_create_fd(fileno(smtp_client->f), (size_t)-1, FALSE);
	lmtp_client_send(client, input);
	i_stream_unref(&input);

	if (!smtp_client->finished)
		io_loop_run(ioloop);
	io_loop_destroy(&ioloop);
	return smtp_client->success ? 0 : -1;
}

int smtp_client_close(struct smtp_client *client)
{
	int ret;

	if (!client->use_smtp)
		return smtp_client_close_sendmail(client);

	/* the mail has been written to a file. now actually send it. */
	ret = smtp_client_send(client);

	fclose(client->f);
	i_free(client->return_path);
	i_free(client->destination);
	i_free(client->temp_path);
	i_free(client);
	return ret < 0 ? EX_TEMPFAIL : 0;
}
