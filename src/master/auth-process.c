/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "env-util.h"
#include "fd-close-on-exec.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "auth-process.h"

#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/stat.h>

#define MAX_INBUF_SIZE \
	(sizeof(struct auth_master_reply) + AUTH_MASTER_MAX_REPLY_DATA_SIZE)

struct auth_process_group {
	struct auth_process_group *next;

	int listen_fd;
	struct auth_settings *set;

	unsigned int process_count;
	struct auth_process *processes;
};

struct auth_process {
	struct auth_process *next;

        struct auth_process_group *group;
	pid_t pid;
	int fd;
	struct io *io;
	struct istream *input;
	struct ostream *output;

	struct auth_master_reply auth_reply;

	struct hash_table *requests;

	unsigned int initialized:1;
	unsigned int in_auth_reply:1;
};

static struct timeout *to;
static unsigned int auth_tag;
static struct auth_process_group *process_groups;

static void auth_process_destroy(struct auth_process *p);

static int handle_reply(struct auth_process *process,
			struct auth_master_reply *reply,
			const unsigned char *data)
{
	size_t nul_pos;
	void *context;

	context = hash_lookup(process->requests, POINTER_CAST(reply->tag));
	if (context == NULL) {
		i_error("Auth process %s sent unrequested reply with tag %u",
			dec2str(process->pid), reply->tag);
		return TRUE;
	}

	/* make sure the reply looks OK */
	if (reply->data_size == 0) {
		nul_pos = 0;
		data = (const unsigned char *) "";
	} else {
		nul_pos = reply->data_size-1;
	}

	if (data[nul_pos] != '\0') {
		i_error("Auth process %s sent invalid reply",
			dec2str(process->pid));
		return FALSE;
	}

	/* fix the request so that all the values point to \0 terminated
	   strings */
	if (reply->system_user_idx >= reply->data_size)
		reply->system_user_idx = nul_pos;
	if (reply->virtual_user_idx >= reply->data_size)
		reply->virtual_user_idx = nul_pos;
	if (reply->home_idx >= reply->data_size)
		reply->home_idx = nul_pos;
	if (reply->mail_idx >= reply->data_size)
		reply->mail_idx = nul_pos;

	auth_master_callback(reply, data, context);
	hash_remove(process->requests, POINTER_CAST(reply->tag));
	return TRUE;
}

void auth_process_request(struct auth_process *process, unsigned int login_pid,
			  unsigned int login_id, void *context)
{
	struct auth_master_request req;
	ssize_t ret;

	req.tag = ++auth_tag;
	req.id = login_id;
	req.login_pid = login_pid;

	ret = o_stream_send(process->output, &req, sizeof(req));
	if ((size_t)ret != sizeof(req)) {
		if (ret >= 0) {
			/* FIXME: well .. I'm not sure if it'd be better to
			   just block here. I don't think this condition should
			   happen often, so this could mean that the auth
			   process is stuck. Or that the computer is just
			   too heavily loaded. Possibility to block infinitely
			   is annoying though, so for now don't do it. */
			i_warning("Auth process %s transmit buffer full, "
				  "killing..", dec2str(process->pid));
		}
		auth_process_destroy(process);
		return;
	}

	hash_insert(process->requests, POINTER_CAST(req.tag), context);
}

static void auth_process_input(void *context)
{
	struct auth_process *p = context;
	const unsigned char *data;
	size_t size;

	switch (i_stream_read(p->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_process_destroy(p);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth process %s sent us more than %d "
			"bytes of data", dec2str(p->pid), (int)MAX_INBUF_SIZE);
		auth_process_destroy(p);
		return;
	}

	if (!p->initialized) {
		data = i_stream_get_data(p->input, &size);
		i_assert(size > 0);

		if (data[0] != 'O') {
			i_fatal("Auth process sent invalid initialization "
				"notification");
		}

		i_stream_skip(p->input, 1);

		p->initialized = TRUE;
	}

	for (;;) {
		if (!p->in_auth_reply) {
			data = i_stream_get_data(p->input, &size);
			if (size < sizeof(p->auth_reply))
				break;

			p->in_auth_reply = TRUE;
			memcpy(&p->auth_reply, data, sizeof(p->auth_reply));

			i_stream_skip(p->input, sizeof(p->auth_reply));
		}

		data = i_stream_get_data(p->input, &size);
		if (size < p->auth_reply.data_size)
			break;

		/* reply is now read */
		if (!handle_reply(p, &p->auth_reply, data)) {
			auth_process_destroy(p);
			break;
		}

		p->in_auth_reply = FALSE;
		i_stream_skip(p->input, p->auth_reply.data_size);
	}
}

static struct auth_process *
auth_process_new(pid_t pid, int fd, struct auth_process_group *group)
{
	struct auth_process *p;

	PID_ADD_PROCESS_TYPE(pid, PROCESS_TYPE_AUTH);

	p = i_new(struct auth_process, 1);
	p->group = group;
	p->pid = pid;
	p->fd = fd;
	p->io = io_add(fd, IO_READ, auth_process_input, p);
	p->input = i_stream_create_file(fd, default_pool,
					MAX_INBUF_SIZE, FALSE);
	p->output = o_stream_create_file(fd, default_pool,
					 sizeof(struct auth_master_request)*100,
					 IO_PRIORITY_DEFAULT, FALSE);
	p->requests = hash_create(default_pool, default_pool, 0, NULL, NULL);

	p->next = group->processes;
	group->processes = p;
	group->process_count++;
	return p;
}

static void request_hash_destroy(void *key __attr_unused__,
				 void *value, void *context __attr_unused__)
{
	auth_master_callback(NULL, NULL, value);
}

static void auth_process_destroy(struct auth_process *p)
{
	struct auth_process **pos;

	if (!p->initialized && io_loop_is_running(ioloop)) {
		i_error("Auth process died too early - shutting down");
		io_loop_stop(ioloop);
	}

	for (pos = &p->group->processes; *pos != NULL; pos = &(*pos)->next) {
		if (*pos == p) {
			*pos = p->next;
			break;
		}
	}
	p->group->process_count--;

	hash_foreach(p->requests, request_hash_destroy, NULL);
	hash_destroy(p->requests);

	i_stream_unref(p->input);
	o_stream_unref(p->output);
	io_remove(p->io);
	if (close(p->fd) < 0)
		i_error("close(auth) failed: %m");
	i_free(p);
}

static pid_t create_auth_process(struct auth_process_group *group)
{
	static char *argv[] = { NULL, NULL };
	struct passwd *pwd;
	pid_t pid;
	int fd[2], i;

	if ((pwd = getpwnam(group->set->user)) == NULL)
		i_fatal("Auth user doesn't exist: %s", group->set->user);

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
		auth_process_new(pid, fd[0], group);
		(void)close(fd[1]);
		return pid;
	}

	/* move master communication handle to 0 */
	if (dup2(fd[1], 0) < 0)
		i_fatal("login: dup2(0) failed: %m");

	(void)close(fd[0]);
	(void)close(fd[1]);

	/* set stdout to /dev/null, so anything written into it gets ignored.
	   leave stderr alone, we might want to use it for logging. */
	if (dup2(null_fd, 1) < 0)
		i_fatal("login: dup2(1) failed: %m");

	child_process_init_env();

	/* move login communication handle to 3. do it last so we can be
	   sure it's not closed afterwards. */
	if (group->listen_fd != 3) {
		if (dup2(group->listen_fd, 3) < 0)
			i_fatal("login: dup2() failed: %m");
	}

	for (i = 0; i <= 3; i++)
		fd_close_on_exec(i, FALSE);

	/* setup access environment */
	restrict_access_set_env(group->set->user, pwd->pw_uid, pwd->pw_gid,
				group->set->chroot);

	/* set other environment */
	env_put(t_strconcat("AUTH_PROCESS=", dec2str(getpid()), NULL));
	env_put(t_strconcat("MECHANISMS=", group->set->mechanisms, NULL));
	env_put(t_strconcat("REALMS=", group->set->realms, NULL));
	env_put(t_strconcat("DEFAULT_REALM=", group->set->default_realm, NULL));
	env_put(t_strconcat("USERDB=", group->set->userdb, NULL));
	env_put(t_strconcat("PASSDB=", group->set->passdb, NULL));
	env_put(t_strconcat("USERNAME_CHARS=", group->set->username_chars, NULL));
	env_put(t_strconcat("ANONYMOUS_USERNAME=",
			    group->set->anonymous_username, NULL));

	if (group->set->use_cyrus_sasl)
		env_put("USE_CYRUS_SASL=1");
	if (group->set->verbose)
		env_put("VERBOSE=1");

	restrict_process_size(group->set->process_size, (unsigned int)-1);

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

	/* hide the path, it's ugly */
	argv[0] = strrchr(group->set->executable, '/');
	if (argv[0] == NULL)
		argv[0] = i_strdup(group->set->executable);
	else
		argv[0]++;

	execv(group->set->executable, argv);

	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m",
		       group->set->executable);
	return -1;
}

struct auth_process *auth_process_find(unsigned int pid)
{
	struct auth_process_group *group;
	struct auth_process *p;

	for (group = process_groups; group != NULL; group = group->next) {
		for (p = group->processes; p != NULL; p = p->next) {
			if ((unsigned int)p->pid == pid)
				return p;
		}
	}

	return NULL;
}

static void auth_process_group_create(struct auth_settings *auth_set)
{
	struct auth_process_group *group;
	const char *path;

	group = i_new(struct auth_process_group, 1);
	group->set = auth_set;

	/* create socket for listening auth requests from login */
	path = t_strconcat(set->login_dir, "/", auth_set->name, NULL);
	(void)unlink(path);
        (void)umask(0117); /* we want 0660 mode for the socket */

	group->listen_fd = net_listen_unix(path);
	if (group->listen_fd < 0)
		i_fatal("Can't listen in UNIX socket %s: %m", path);
	net_set_nonblock(group->listen_fd, TRUE);
	fd_close_on_exec(group->listen_fd, TRUE);

	/* set correct permissions */
	if (chown(path, geteuid(), set->login_gid) < 0) {
		i_fatal("login: chown(%s, %s, %s) failed: %m",
			path, dec2str(geteuid()), dec2str(set->login_gid));
	}

	group->next = process_groups;
	process_groups = group;
}

static void auth_process_group_destroy(struct auth_process_group *group)
{
	struct auth_process *next;

	while (group->processes != NULL) {
		next = group->processes->next;
		auth_process_destroy(group->processes);
                group->processes = next;
	}

	(void)unlink(t_strconcat(set->login_dir, "/", group->set->name, NULL));

	if (close(group->listen_fd) < 0)
		i_error("close(auth group %s) failed: %m", group->set->name);
	i_free(group);
}

void auth_processes_destroy_all(void)
{
	struct auth_process_group *next;

	while (process_groups != NULL) {
		next = process_groups->next;
		auth_process_group_destroy(process_groups);
		process_groups = next;
	}
}

static void
auth_processes_start_missing(void *context __attr_unused__)
{
	struct auth_settings *auth_set;
	struct auth_process_group *group;
	unsigned int count;

	if (process_groups == NULL) {
		/* first time here, create the groups */
		auth_set = set->auths;
		for (; auth_set != NULL; auth_set = auth_set->next)
                        auth_process_group_create(auth_set);
	}

	for (group = process_groups; group != NULL; group = group->next) {
		count = group->process_count;
		for (; count < group->set->count; count++)
			(void)create_auth_process(group);
	}
}

void auth_processes_init(void)
{
	process_groups = NULL;
	to = timeout_add(1000, auth_processes_start_missing, NULL);
}

void auth_processes_deinit(void)
{
	timeout_remove(to);
	auth_processes_destroy_all();
}
