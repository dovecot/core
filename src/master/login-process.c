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
#include "mail-process.h"
#include "master-login-interface.h"

#include <unistd.h>
#include <syslog.h>

struct login_group {
	struct login_group *next;

	struct login_settings *set;

	unsigned int processes;
	unsigned int listening_processes;
	unsigned int wanted_processes_count;

	struct login_process *oldest_nonlisten_process;
	struct login_process *newest_nonlisten_process;

	const char *executable;
	unsigned int process_size;
	int process_type;
	int *listen_fd, *ssl_listen_fd;
};

struct login_process {
	struct login_group *group;
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

static unsigned int auth_id_counter, login_pid_counter;
static struct timeout *to;
static struct io *io_listen;

static struct hash_table *processes;
static struct login_group *login_groups;

static void login_process_destroy(struct login_process *p);
static void login_process_unref(struct login_process *p);
static int login_process_init_group(struct login_process *p);

static void login_group_create(struct login_settings *login_set)
{
	struct login_group *group;

	if (strstr(set->protocols, login_set->name) == NULL) {
		/* not enabled */
		return;
	}

	group = i_new(struct login_group, 1);
	group->set = login_set;

	if (strcmp(login_set->name, "imap") == 0) {
		group->executable = set->imap_executable;
		group->process_size = set->imap_process_size;
		group->process_type = PROCESS_TYPE_IMAP;
		group->listen_fd = &mail_fd[FD_IMAP];
		group->ssl_listen_fd = &mail_fd[FD_IMAPS];
	} else if (strcmp(login_set->name, "pop3") == 0) {
		group->executable = set->pop3_executable;
		group->process_size = set->pop3_process_size;
		group->process_type = PROCESS_TYPE_POP3;
		group->listen_fd = &mail_fd[FD_POP3];
		group->ssl_listen_fd = &mail_fd[FD_POP3S];
	} else
		i_panic("Unknown login group name '%s'", login_set->name);

	group->next = login_groups;
	login_groups = group;
}

static void login_group_destroy(struct login_group *group)
{
	i_free(group);
}

void auth_master_callback(struct auth_master_reply *reply,
			  const unsigned char *data, void *context)
{
	struct login_auth_request *request = context;
	struct master_login_reply master_reply;

	if (reply == NULL || !reply->success)
		master_reply.success = FALSE;
	else {
		struct login_group *group = request->process->group;

		master_reply.success =
			create_mail_process(request->fd, &request->ip,
					    group->executable,
					    group->process_size,
					    group->process_type, reply,
					    (const char *) data);
	}

	/* reply to login */
	master_reply.tag = request->login_tag;

	if (o_stream_send(request->process->output, &master_reply,
			  sizeof(master_reply)) < 0)
		login_process_destroy(request->process);

	if (close(request->fd) < 0)
		i_error("close(mail client) failed: %m");
	login_process_unref(request->process);
	i_free(request);
}

static void login_process_mark_nonlistening(struct login_process *p)
{
	if (!p->listening) {
		i_error("login: received another \"not listening\" "
			"notification (if you can't login at all, "
			"see src/lib/fdpass.c)");
		return;
	}

	p->listening = FALSE;

	if (p->group != NULL) {
		p->group->listening_processes--;
		p->prev_nonlisten = p->group->newest_nonlisten_process;

		if (p->group->newest_nonlisten_process != NULL)
			p->group->newest_nonlisten_process->next_nonlisten = p;
		p->group->newest_nonlisten_process = p;

		if (p->group->oldest_nonlisten_process == NULL)
			p->group->oldest_nonlisten_process = p;
	}
}

static struct login_group *login_group_process_find(const char *name)
{
	struct login_group *group;
	struct login_settings *login;

	if (login_groups == NULL) {
		for (login = set->logins; login != NULL; login = login->next)
			login_group_create(login);
	}

	for (group = login_groups; group != NULL; group = group->next) {
		if (strcmp(group->set->name, name) == 0)
			return group;
	}

	return NULL;
}

static int login_process_read_group(struct login_process *p)
{
	struct login_group *group;
	const char *name;
	char buf[256];
	unsigned int len;
	ssize_t ret;

	/* read length */
	ret = read(p->fd, buf, 1);
	if (ret != 1)
		len = 0;
	else {
		len = buf[0];
		if (len >= sizeof(buf)) {
			i_error("login: Process name length too large");
			return FALSE;
		}

		ret = read(p->fd, buf, len);
	}

	if (ret < 0)
		i_error("login: read() failed: %m");
	else if (len == 0 || (size_t)ret != len)
		i_error("login: Process name wasn't sent");
	else {
		name = t_strndup(buf, len);
		group = login_group_process_find(name);
		if (group == NULL) {
			i_error("login: Unknown process group '%s'", name);
			return FALSE;
		}

		p->group = group;
		return login_process_init_group(p);
	}
	return FALSE;
}

static void login_process_input(void *context)
{
	struct login_process *p = context;
	struct auth_process *auth_process;
	struct login_auth_request *authreq;
	struct master_login_request req;
	int client_fd;
	ssize_t ret;

	if (p->group == NULL) {
		/* we want to read the group */
		if (!login_process_read_group(p))
			login_process_destroy(p);
		return;
	}

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
				i_error("close(mail client) failed: %m");
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

static struct login_process *
login_process_new(struct login_group *group, pid_t pid, int fd)
{
	struct login_process *p;

	i_assert(pid != 0);

	p = i_new(struct login_process, 1);
	p->group = group;
	p->refcount = 1;
	p->pid = pid;
	p->fd = fd;
	p->listening = TRUE;
	p->io = io_add(fd, IO_READ, login_process_input, p);
	p->output = o_stream_create_file(fd, default_pool,
					 sizeof(struct master_login_reply)*10,
					 IO_PRIORITY_DEFAULT, FALSE);

	PID_ADD_PROCESS_TYPE(pid, PROCESS_TYPE_LOGIN);
	hash_insert(processes, POINTER_CAST(pid), p);

	if (p->group != NULL) {
		p->group->processes++;
		p->group->listening_processes++;
	}
	return p;
}

static void login_process_remove_from_lists(struct login_process *p)
{
	if (p->group == NULL)
		return;

	if (p == p->group->oldest_nonlisten_process)
		p->group->oldest_nonlisten_process = p->next_nonlisten;
	else
		p->prev_nonlisten->next_nonlisten = p->next_nonlisten;

	if (p == p->group->newest_nonlisten_process)
		p->group->newest_nonlisten_process = p->prev_nonlisten;
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

	if (p->listening && p->group != NULL)
		p->group->listening_processes--;

	o_stream_close(p->output);
	io_remove(p->io);
	if (close(p->fd) < 0)
		i_error("close(login) failed: %m");

	if (!p->listening)
		login_process_remove_from_lists(p);

	if (p->group != NULL)
		p->group->processes--;

	if (p->pid != 0)
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

static void login_process_init_env(struct login_group *group, pid_t pid)
{
	child_process_init_env();

	/* setup access environment - needs to be done after
	   clean_child_process() since it clears environment */
	restrict_access_set_env(group->set->user,
				group->set->uid, set->login_gid,
				set->login_chroot ? set->login_dir : NULL);

	env_put("DOVECOT_MASTER=1");

	if (!set->ssl_disable) {
		env_put(t_strconcat("SSL_CERT_FILE=",
				    set->ssl_cert_file, NULL));
		env_put(t_strconcat("SSL_KEY_FILE=", set->ssl_key_file, NULL));
		env_put(t_strconcat("SSL_PARAM_FILE=",
				    set->ssl_parameters_file, NULL));
	}

	if (set->disable_plaintext_auth)
		env_put("DISABLE_PLAINTEXT_AUTH=1");
	if (set->verbose_proctitle)
		env_put("VERBOSE_PROCTITLE=1");
	if (set->verbose_ssl)
		env_put("VERBOSE_SSL=1");

	if (group->set->process_per_connection) {
		env_put("PROCESS_PER_CONNECTION=1");
		env_put("MAX_LOGGING_USERS=1");
	} else {
		env_put(t_strdup_printf("MAX_LOGGING_USERS=%u",
					group->set->max_logging_users));
	}

	env_put(t_strdup_printf("PROCESS_UID=%s", dec2str(pid)));
}

static pid_t create_login_process(struct login_group *group)
{
	static const char *argv[] = { NULL, NULL };
	pid_t pid;
	int fd[2];

	if (group->set->process_per_connection &&
	    group->processes - group->listening_processes >=
	    group->set->max_logging_users) {
		if (group->oldest_nonlisten_process != NULL)
			login_process_destroy(group->oldest_nonlisten_process);
	}

	if (group->set->uid == 0)
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
		net_set_nonblock(fd[0], TRUE);
		fd_close_on_exec(fd[0], TRUE);
		(void)login_process_new(group, pid, fd[0]);
		(void)close(fd[1]);
		return pid;
	}

	/* move the listen handle */
	if (dup2(*group->listen_fd, LOGIN_LISTEN_FD) < 0)
		i_fatal("login: dup2(listen_fd) failed: %m");
	fd_close_on_exec(LOGIN_LISTEN_FD, FALSE);

	/* move the SSL listen handle */
	if (dup2(*group->ssl_listen_fd, LOGIN_SSL_LISTEN_FD) < 0)
		i_fatal("login: dup2(ssl_listen_fd) failed: %m");
	fd_close_on_exec(LOGIN_SSL_LISTEN_FD, FALSE);

	/* move communication handle */
	if (dup2(fd[1], LOGIN_MASTER_SOCKET_FD) < 0)
		i_fatal("login: dup2(master) failed: %m");
	fd_close_on_exec(LOGIN_MASTER_SOCKET_FD, FALSE);

	(void)close(fd[0]);
	(void)close(fd[1]);

	login_process_init_env(group, getpid());

	if (!set->login_chroot) {
		/* no chrooting, but still change to the directory */
		if (chdir(set->login_dir) < 0)
			i_fatal("chdir(%s) failed: %m", set->login_dir);
	}

	restrict_process_size(group->set->process_size, (unsigned int)-1);

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

	/* hide the path, it's ugly */
	argv[0] = strrchr(group->set->executable, '/');
	if (argv[0] == NULL) argv[0] = group->set->executable; else argv[0]++;

	execv(group->set->executable, (char **) argv);

	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", argv[0]);
	return -1;
}

void login_process_abormal_exit(pid_t pid)
{
	struct login_process *p;

	/* don't start raising the process count if they're dying all
	   the time */
	p = hash_lookup(processes, POINTER_CAST(pid));
	if (p != NULL && p->group != NULL)
		p->group->wanted_processes_count = 0;
}

static void login_hash_destroy(void *key __attr_unused__, void *value,
			       void *context __attr_unused__)
{
	login_process_destroy(value);
}

void login_processes_destroy_all(void)
{
	hash_foreach(processes, login_hash_destroy, NULL);

	while (login_groups != NULL) {
		struct login_group *group = login_groups;

		login_groups = group->next;
		login_group_destroy(group);
	}
}

static void login_group_start_missings(struct login_group *group)
{
	if (!group->set->process_per_connection) {
		/* create max. one process every second, that way if it keeps
		   dying all the time we don't eat all cpu with fork()ing. */
		if (group->listening_processes < group->set->processes_count)
			(void)create_login_process(group);
		return;
	}

	/* we want to respond fast when multiple clients are connecting
	   at once, but we also want to prevent fork-bombing. use the
	   same method as apache: check once a second if we need new
	   processes. if yes and we've used all the existing processes,
	   double their amount (unless we've hit the high limit).
	   Then for each second that didn't use all existing processes,
	   drop the max. process count by one. */
	if (group->wanted_processes_count < group->set->processes_count)
		group->wanted_processes_count = group->set->processes_count;
	else if (group->listening_processes == 0)
		group->wanted_processes_count *= 2;
	else if (group->wanted_processes_count > group->set->processes_count)
		group->wanted_processes_count--;

	if (group->wanted_processes_count > group->set->max_processes_count)
		group->wanted_processes_count = group->set->max_processes_count;

	while (group->listening_processes < group->wanted_processes_count)
		(void)create_login_process(group);
}

static void
login_processes_start_missing(void *context __attr_unused__)
{
	struct login_group *group;
	struct login_settings *login;

	if (login_groups == NULL) {
		for (login = set->logins; login != NULL; login = login->next)
			login_group_create(login);
	}

	for (group = login_groups; group != NULL; group = group->next)
		login_group_start_missings(group);
}

static int login_process_send_env(struct login_process *p)
{
	extern char **environ;
	char **env;
	size_t len;
	int ret = 0;

	/* this will clear our environment. luckily we don't need it. */
	login_process_init_env(p->group, p->pid);

	for (env = environ; *env != NULL; env++) {
		len = strlen(*env);

		if (o_stream_send(p->output, *env, len) != (ssize_t)len ||
		    o_stream_send(p->output, "\n", 1) != 1) {
			ret = -1;
			break;
		}
	}

	if (ret == 0 && o_stream_send(p->output, "\n", 1) != 1)
		ret = -1;

	env_clean();
	return ret;
}

static int login_process_init_group(struct login_process *p)
{
	p->group->processes++;
	p->group->listening_processes++;

	if (login_process_send_env(p) < 0) {
		i_error("login: Couldn't send environment");
		return FALSE;
	}

	return TRUE;
}

static void inetd_login_accept(void *context __attr_unused__)
{
        struct login_process *p;
	int fd;

	fd = net_accept(inetd_login_fd, NULL, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_fatal("accept(inetd_login_fd) failed: %m");
	} else {
		net_set_nonblock(fd, TRUE);
		fd_close_on_exec(fd, TRUE);

		p = login_process_new(NULL, ++login_pid_counter, fd);
		p->initialized = TRUE;
	}
}

void login_processes_init(void)
{
	auth_id_counter = 0;
        login_pid_counter = 0;
	login_groups = NULL;

	processes = hash_create(default_pool, default_pool, 128, NULL, NULL);
	if (!IS_INETD()) {
		to = timeout_add(1000, login_processes_start_missing, NULL);
		io_listen = NULL;
	} else {
		to = NULL;
		io_listen = io_add(inetd_login_fd, IO_READ,
				   inetd_login_accept, NULL);
	}
}

void login_processes_deinit(void)
{
	if (to != NULL)
		timeout_remove(to);
	if (io_listen != NULL)
		io_remove(io_listen);

        login_processes_destroy_all();
	hash_destroy(processes);
}
