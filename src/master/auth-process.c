/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "env-util.h"
#include "fd-close-on-exec.h"
#include "network.h"
#include "ostream.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "auth-process.h"

#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/stat.h>

typedef struct _WaitingRequest WaitingRequest;

struct _AuthProcess {
	AuthProcess *next;

	char *name;
	pid_t pid;
	int fd;
	IO io;
	OStream *output;

	unsigned int reply_pos;
	char reply_buf[sizeof(AuthCookieReplyData)];

	WaitingRequest *requests, **next_request;
};

struct _WaitingRequest {
        WaitingRequest *next;
	int id;

	AuthCallback callback;
	void *context;
};

static Timeout to;
static AuthProcess *processes;

static void auth_process_destroy(AuthProcess *p);

static void push_request(AuthProcess *process, int id,
			 AuthCallback callback, void *context)
{
	WaitingRequest *req;

	req = i_new(WaitingRequest, 1);
	req->id = id;
	req->callback = callback;
	req->context = context;

	*process->next_request = req;
	process->next_request = &req->next;
}

static void pop_request(AuthProcess *process, AuthCookieReplyData *reply)
{
	WaitingRequest *req;

	req = process->requests;
	if (req == NULL) {
		i_warning("imap-auth %s sent us unrequested reply for id %d",
			  dec2str(process->pid), reply->id);
		return;
	}

	if (reply->id != req->id) {
		i_fatal("imap-auth %s sent invalid id for reply "
			"(got %d, expecting %d)",
			dec2str(process->pid), reply->id, req->id);
	}

	/* auth process isn't trusted, validate all data to make sure
	   it's not trying to exploit us */
	if (!VALIDATE_STR(reply->system_user) ||
	    !VALIDATE_STR(reply->virtual_user) || !VALIDATE_STR(reply->mail) ||
	    !VALIDATE_STR(reply->home)) {
		i_error("auth: Received corrupted data");
		auth_process_destroy(process);
		return;
	}

	process->requests = req->next;
	if (process->requests == NULL)
		process->next_request = &process->requests;

	req->callback(reply, req->context);

	i_free(req);
}

static void auth_process_input(void *context, int fd, IO io __attr_unused__)
{
	AuthProcess *p = context;
	int ret;

	ret = net_receive(fd, p->reply_buf + p->reply_pos,
			  sizeof(p->reply_buf) - p->reply_pos);
	if (ret < 0) {
		/* disconnected */
		auth_process_destroy(p);
		return;
	}

	p->reply_pos += ret;
	if (p->reply_pos < sizeof(p->reply_buf))
		return;

	/* reply is now read */
	pop_request(p, (AuthCookieReplyData *) p->reply_buf);
	p->reply_pos = 0;
}

static AuthProcess *auth_process_new(pid_t pid, int fd, const char *name)
{
	AuthProcess *p;

	PID_ADD_PROCESS_TYPE(pid, PROCESS_TYPE_AUTH);

	p = i_new(AuthProcess, 1);
	p->name = i_strdup(name);
	p->pid = pid;
	p->fd = fd;
	p->io = io_add(fd, IO_READ, auth_process_input, p);
	p->output = o_stream_create_file(fd, default_pool,
					 sizeof(AuthCookieRequestData)*100,
					 IO_PRIORITY_DEFAULT, FALSE);

	p->next_request = &p->requests;

	p->next = processes;
	processes = p;
	return p;
}

static void auth_process_destroy(AuthProcess *p)
{
	AuthProcess **pos;
	WaitingRequest *next;

	for (pos = &processes; *pos != NULL; pos = &(*pos)->next) {
		if (*pos == p) {
			*pos = p->next;
			break;
		}
	}

	for (; p->requests != NULL; p->requests = next) {
		next = p->requests->next;

		p->requests->callback(NULL, p->requests->context);
		i_free(p->requests);
	}

	(void)unlink(t_strconcat(set_login_dir, "/", p->name, NULL));

	o_stream_unref(p->output);
	io_remove(p->io);
	if (close(p->fd) < 0)
		i_error("close(auth) failed: %m");
	i_free(p->name);
	i_free(p);
}

static pid_t create_auth_process(AuthConfig *config)
{
	static char *argv[] = { NULL, NULL };
	const char *path;
	struct passwd *pwd;
	pid_t pid;
	int fd[2], listen_fd, i;

	if ((pwd = getpwnam(config->user)) == NULL)
		i_fatal("Auth user doesn't exist: %s", config->user);

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
		auth_process_new(pid, fd[0], config->name);
		(void)close(fd[1]);
		return pid;
	}

	/* create socket for listening auth requests from imap-login */
	path = t_strconcat(set_login_dir, "/", config->name, NULL);
	(void)unlink(path);
        (void)umask(0177); /* we want 0600 mode for the socket */

	listen_fd = net_listen_unix(path);
	if (listen_fd < 0)
		i_fatal("Can't listen in UNIX socket %s: %m", path);

	i_assert(listen_fd > 2);

	/* set correct permissions */
	if (chown(path, set_login_uid, set_login_gid) < 0) {
		i_fatal("login: chown(%s, %s, %s) failed: %m",
			path, dec2str(set_login_uid), dec2str(set_login_gid));
	}

	/* move master communication handle to 0 */
	if (dup2(fd[1], 0) < 0)
		i_fatal("login: dup2(0) failed: %m");

	(void)close(fd[0]);
	(void)close(fd[1]);

	/* set /dev/null handle into 1 and 2, so if something is printed into
	   stdout/stderr it can't go anywhere where it could cause harm */
	if (dup2(null_fd, 1) < 0)
		i_fatal("login: dup2(1) failed: %m");
	if (dup2(null_fd, 2) < 0)
		i_fatal("login: dup2(2) failed: %m");

	clean_child_process();

	/* move login communication handle to 3. do it last so we can be
	   sure it's not closed afterwards. */
	if (listen_fd != 3) {
		if (dup2(listen_fd, 3) < 0)
			i_fatal("login: dup2() failed: %m");
		(void)close(listen_fd);
	}

	for (i = 0; i <= 2; i++)
		fd_close_on_exec(i, FALSE);

	/* setup access environment - needs to be done after
	   clean_child_process() since it clears environment */
	restrict_access_set_env(config->user, pwd->pw_uid, pwd->pw_gid,
				config->chroot);

	/* set other environment */
	env_put(t_strconcat("AUTH_PROCESS=", dec2str(getpid()), NULL));
	env_put(t_strconcat("METHODS=", config->methods, NULL));
	env_put(t_strconcat("REALMS=", config->realms, NULL));
	env_put(t_strconcat("USERINFO=", config->userinfo, NULL));
	env_put(t_strconcat("USERINFO_ARGS=", config->userinfo_args,
				    NULL));

	restrict_process_size(config->process_size);

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

	/* hide the path, it's ugly */
	argv[0] = strrchr(config->executable, '/');
	if (argv[0] == NULL) argv[0] = config->executable; else argv[0]++;

	execv(config->executable, (char **) argv);

	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", argv[0]);
	return -1;
}

AuthProcess *auth_process_find(int id)
{
	AuthProcess *p;

	for (p = processes; p != NULL; p = p->next) {
		if (p->pid == id)
			return p;
	}

	return NULL;
}

void auth_process_request(AuthProcess *process, int id,
			  unsigned char cookie[AUTH_COOKIE_SIZE],
			  AuthCallback callback, void *context)
{
	AuthCookieRequestData req;

	req.id = id;
	memcpy(req.cookie, cookie, AUTH_COOKIE_SIZE);

	if (o_stream_send(process->output, &req, sizeof(req)) < 0)
		auth_process_destroy(process);

	push_request(process, id, callback, context);
}

static int auth_process_get_count(const char *name)
{
	AuthProcess *p;
	int count = 0;

	for (p = processes; p != NULL; p = p->next) {
		if (strcmp(p->name, name) == 0)
			count++;
	}

	return count;
}

void auth_processes_destroy_all(void)
{
	AuthProcess *next;

	while (processes != NULL) {
		next = processes->next;
		auth_process_destroy(processes);
                processes = next;
	}
}

static void auth_processes_start_missing(void *context __attr_unused__,
					 Timeout timeout __attr_unused__)
{
	AuthConfig *config;
	int count;

        config = auth_processes_config;
	for (; config != NULL; config = config->next) {
		count = auth_process_get_count(config->name);
		for (; count < config->count; count++)
			(void)create_auth_process(config);
	}
}

void auth_processes_init(void)
{
	processes = NULL;
	to = timeout_add(1000, auth_processes_start_missing, NULL);
}

void auth_processes_deinit(void)
{
	timeout_remove(to);
	auth_processes_destroy_all();
}
