/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "network.h"
#include "ostream.h"
#include "fdpass.h"
#include "fd-close-on-exec.h"
#include "env-util.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "login-process.h"
#include "auth-process.h"
#include "imap-process.h"
#include "master-login-interface.h"

#include <unistd.h>
#include <syslog.h>

struct login_process {
	struct login_process *prev_nonlisten, *next_nonlisten;
	int refcount;

	pid_t pid;
	int fd;
	struct io *io;
	struct ostream *output;
	unsigned int initialized:1;
	unsigned int listening:1;
	unsigned int destroyed:1;
};

struct login_auth_request {
	struct login_process *process;
	unsigned int tag;

	unsigned int login_tag;
	int fd;

	struct ip_addr ip;
};

static unsigned int auth_id_counter;
static struct timeout *to;

static struct hash_table *processes;
static struct login_process *oldest_nonlisten_process;
static struct login_process *newest_nonlisten_process;
static unsigned int listening_processes;
static unsigned int wanted_processes_count;

static void login_process_destroy(struct login_process *p);
static void login_process_unref(struct login_process *p);

void auth_master_callback(struct auth_master_reply *reply,
			  const unsigned char *data, void *context)
{
	struct login_auth_request *request = context;
	struct master_login_reply master_reply;

	if (reply == NULL || !reply->success)
		master_reply.success = FALSE;
	else {
		master_reply.success =
			create_imap_process(request->fd, &request->ip, reply,
					    (const char *) data);
	}

	/* reply to login */
	master_reply.tag = request->login_tag;

	if (o_stream_send(request->process->output, &master_reply,
			  sizeof(master_reply)) < 0)
		login_process_destroy(request->process);

	if (close(request->fd) < 0)
		i_error("close(imap client) failed: %m");
	login_process_unref(request->process);
	i_free(request);
}

static void login_process_mark_nonlistening(struct login_process *p)
{
	if (!p->listening) {
		i_error("login: received another \"not listening\" "
			"notification");
		return;
	}

	p->listening = FALSE;
	listening_processes--;

	p->prev_nonlisten = newest_nonlisten_process;

	if (newest_nonlisten_process != NULL)
		newest_nonlisten_process->next_nonlisten = p;
	newest_nonlisten_process = p;

	if (oldest_nonlisten_process == NULL)
		oldest_nonlisten_process = p;
}

static void login_process_input(void *context)
{
	struct login_process *p = context;
	struct auth_process *auth_process;
	struct login_auth_request *authreq;
	struct master_login_request req;
	int client_fd, ret;

	ret = fd_read(p->fd, &req, sizeof(req), &client_fd);
	if (ret != sizeof(req)) {
		if (ret == 0) {
			/* disconnected, ie. the login process died */
		} else if (ret > 0) {
			/* req wasn't fully read */
			i_error("login: fd_read() couldn't read all req");
		} else {
			i_error("login: fd_read() failed: %m");
		}

		if (client_fd != -1) {
			if (close(client_fd) < 0)
				i_error("close(imap client) failed: %m");
		}

		login_process_destroy(p);
		return;
	}

	if (client_fd == -1) {
		/* just a notification that the login process */
		if (!p->initialized) {
			/* initialization notify */
			p->initialized = TRUE;;
		} else {
			/* not listening for new connections anymore */
			login_process_mark_nonlistening(p);
		}
		return;
	}

	fd_close_on_exec(client_fd, TRUE);

	/* ask the cookie from the auth process */
	authreq = i_new(struct login_auth_request, 1);
	p->refcount++;
	authreq->process = p;
	authreq->tag = ++auth_id_counter;
	authreq->login_tag = req.tag;
	authreq->fd = client_fd;
	authreq->ip = req.ip;

	auth_process = auth_process_find(req.auth_pid);
	if (auth_process == NULL) {
		i_error("login: Authentication process %u doesn't exist",
			req.auth_pid);
		auth_master_callback(NULL, NULL, authreq);
	} else {
		auth_process_request(auth_process, p->pid,
				     req.auth_id, authreq);
	}
}

static struct login_process *login_process_new(pid_t pid, int fd)
{
	struct login_process *p;

	PID_ADD_PROCESS_TYPE(pid, PROCESS_TYPE_LOGIN);

	p = i_new(struct login_process, 1);
	p->refcount = 1;
	p->pid = pid;
	p->fd = fd;
	p->listening = TRUE;
	p->io = io_add(fd, IO_READ, login_process_input, p);
	p->output = o_stream_create_file(fd, default_pool,
					 sizeof(struct master_login_reply)*10,
					 IO_PRIORITY_DEFAULT, FALSE);

	hash_insert(processes, POINTER_CAST(pid), p);
        listening_processes++;
	return p;
}

static void login_process_remove_from_lists(struct login_process *p)
{
	if (p == oldest_nonlisten_process)
		oldest_nonlisten_process = p->next_nonlisten;
	else
		p->prev_nonlisten->next_nonlisten = p->next_nonlisten;

	if (p == newest_nonlisten_process)
		newest_nonlisten_process = p->prev_nonlisten;
	else
		p->next_nonlisten->prev_nonlisten = p->prev_nonlisten;

	p->next_nonlisten = p->prev_nonlisten = NULL;
}

static void login_process_destroy(struct login_process *p)
{
	if (p->destroyed)
		return;
	p->destroyed = TRUE;

	if (!p->initialized && io_loop_is_running(ioloop)) {
		i_error("Login process died too early - shutting down");
		io_loop_stop(ioloop);
	}
	if (p->listening)
		listening_processes--;

	o_stream_close(p->output);
	io_remove(p->io);
	if (close(p->fd) < 0)
		i_error("close(login) failed: %m");

	if (!p->listening)
		login_process_remove_from_lists(p);

	hash_remove(processes, POINTER_CAST(p->pid));

	login_process_unref(p);
}

static void login_process_unref(struct login_process *p)
{
	if (--p->refcount > 0)
		return;

	o_stream_unref(p->output);
	i_free(p);
}

static pid_t create_login_process(void)
{
	static char *argv[] = { NULL, NULL };
	pid_t pid;
	int fd[2];

	if (set_login_process_per_connection &&
	    hash_size(processes)-listening_processes >= set_max_logging_users) {
		if (oldest_nonlisten_process != NULL)
			login_process_destroy(oldest_nonlisten_process);
	}

	if (set_login_uid == 0)
		i_fatal("Login process must not run as root");

	/* create communication to process with a socket pair */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == -1) {
		i_error("socketpair() failed: %m");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		(void)close(fd[0]);
		(void)close(fd[1]);
		i_error("fork() failed: %m");
		return -1;
	}

	if (pid != 0) {
		/* master */
		fd_close_on_exec(fd[0], TRUE);
		login_process_new(pid, fd[0]);
		(void)close(fd[1]);
		return pid;
	}

	/* move communication handle */
	if (dup2(fd[1], LOGIN_MASTER_SOCKET_FD) < 0)
		i_fatal("login: dup2(master) failed: %m");
	fd_close_on_exec(LOGIN_MASTER_SOCKET_FD, FALSE);

	/* move the listen handle */
	if (dup2(imap_fd, LOGIN_IMAP_LISTEN_FD) < 0)
		i_fatal("login: dup2(imap) failed: %m");
	fd_close_on_exec(LOGIN_IMAP_LISTEN_FD, FALSE);

	/* move the SSL listen handle */
	if (!set_ssl_disable) {
		if (dup2(imaps_fd, LOGIN_IMAPS_LISTEN_FD) < 0)
			i_fatal("login: dup2(imaps) failed: %m");
	} else {
		if (dup2(null_fd, LOGIN_IMAPS_LISTEN_FD) < 0)
			i_fatal("login: dup2(imaps) failed: %m");
	}
	fd_close_on_exec(LOGIN_IMAPS_LISTEN_FD, FALSE);

	/* imap_fd and imaps_fd are closed by clean_child_process() */

	(void)close(fd[0]);
	(void)close(fd[1]);

	clean_child_process();

	/* setup access environment - needs to be done after
	   clean_child_process() since it clears environment */
	restrict_access_set_env(set_login_user, set_login_uid, set_login_gid,
				set_login_chroot ? set_login_dir : NULL);

	if (!set_login_chroot) {
		/* no chrooting, but still change to the directory */
		if (chdir(set_login_dir) < 0)
			i_fatal("chdir(%s) failed: %m", set_login_dir);
	}

	if (!set_ssl_disable) {
		env_put(t_strconcat("SSL_CERT_FILE=", set_ssl_cert_file, NULL));
		env_put(t_strconcat("SSL_KEY_FILE=", set_ssl_key_file, NULL));
		env_put(t_strconcat("SSL_PARAM_FILE=",
				    set_ssl_parameters_file, NULL));
	}

	if (set_disable_plaintext_auth)
		env_put("DISABLE_PLAINTEXT_AUTH=1");
	if (set_verbose_proctitle)
		env_put("VERBOSE_PROCTITLE=1");

	if (set_login_process_per_connection) {
		env_put("PROCESS_PER_CONNECTION=1");
		env_put("MAX_LOGGING_USERS=1");
	} else {
		env_put(t_strdup_printf("MAX_LOGGING_USERS=%u",
					set_max_logging_users));
	}

	env_put(t_strdup_printf("PROCESS_UID=%s", dec2str(getpid())));

	restrict_process_size(set_login_process_size);

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

	/* hide the path, it's ugly */
	argv[0] = strrchr(set_login_executable, '/');
	if (argv[0] == NULL) argv[0] = set_login_executable; else argv[0]++;

	execv(set_login_executable, (char **) argv);

	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", argv[0]);
	return -1;
}

void login_process_abormal_exit(pid_t pid __attr_unused__)
{
	/* don't start raising the process count if they're dying all
	   the time */
	wanted_processes_count = 0;
}

static void login_hash_destroy(void *key __attr_unused__, void *value,
			       void *context __attr_unused__)
{
	login_process_destroy(value);
}

void login_processes_destroy_all(void)
{
	hash_foreach(processes, login_hash_destroy, NULL);

	/* don't double their amount when restarting */
	wanted_processes_count = 0;
}

static void
login_processes_start_missing(void *context __attr_unused__)
{
	if (!set_login_process_per_connection) {
		/* create max. one process every second, that way if it keeps
		   dying all the time we don't eat all cpu with fork()ing. */
		if (listening_processes < set_login_processes_count)
			(void)create_login_process();
	} else {
		/* we want to respond fast when multiple clients are connecting
		   at once, but we also want to prevent fork-bombing. use the
		   same method as apache: check once a second if we need new
		   processes. if yes and we've used all the existing processes,
		   double their amount (unless we've hit the high limit).
		   Then for each second that didn't use all existing processes,
		   drop the max. process count by one. */
		if (wanted_processes_count < set_login_processes_count)
			wanted_processes_count = set_login_processes_count;
		else if (listening_processes == 0)
			wanted_processes_count *= 2;
		else if (wanted_processes_count > set_login_processes_count)
			wanted_processes_count--;

		if (wanted_processes_count > set_login_max_processes_count)
			wanted_processes_count = set_login_max_processes_count;

		while (listening_processes < wanted_processes_count)
			(void)create_login_process();
	}
}

void login_processes_init(void)
{
        auth_id_counter = 0;
	listening_processes = 0;
        wanted_processes_count = 0;
	oldest_nonlisten_process = newest_nonlisten_process = NULL;

	processes = hash_create(default_pool, default_pool, 128, NULL, NULL);
	to = timeout_add(1000, login_processes_start_missing, NULL);
}

void login_processes_deinit(void)
{
	timeout_remove(to);

        login_processes_destroy_all();
	hash_destroy(processes);
}
