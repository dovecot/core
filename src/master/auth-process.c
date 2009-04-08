/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "hash.h"
#include "ioloop.h"
#include "env-util.h"
#include "fd-close-on-exec.h"
#include "unix-socket-create.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "auth-process.h"
#include "child-process.h"
#include "../auth/auth-master-interface.h"
#include "log.h"

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pwd.h>
#include <syslog.h>

#define MAX_INBUF_SIZE 8192
#define MAX_OUTBUF_SIZE 65536

struct auth_process_group {
	struct auth_process_group *next;

	int listen_fd;
	const struct master_settings *master_set;
	const struct master_auth_settings *set;

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

	int worker_listen_fd;
	struct io *worker_io;

	struct hash_table *requests;

	unsigned int external:1;
	unsigned int version_received:1;
	unsigned int initialized:1;
	unsigned int in_auth_reply:1;
};

bool have_initialized_auth_processes = FALSE;

static struct child_process auth_child_process =
	{ MEMBER(type) PROCESS_TYPE_AUTH };
static struct child_process auth_worker_child_process =
	{ MEMBER(type) PROCESS_TYPE_AUTH_WORKER };

static struct timeout *to;
static unsigned int auth_tag;
static struct auth_process_group *process_groups;
static bool auth_stalled = FALSE;

static void auth_process_destroy(struct auth_process *p);
static int create_auth_worker(struct auth_process *process, int fd);
static void auth_processes_start_missing(void *context);

void auth_process_request(struct auth_process *process, unsigned int login_pid,
			  unsigned int login_id,
			  struct login_auth_request *request)
{
	string_t *str;
	ssize_t ret;

	str = t_str_new(256);
	str_printfa(str, "REQUEST\t%u\t%u\t%u\n",
		    ++auth_tag, login_pid, login_id);

	ret = o_stream_send(process->output, str_data(str), str_len(str));
	if (ret != (ssize_t)str_len(str)) {
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
	} else {
		hash_table_insert(process->requests,
				  POINTER_CAST(auth_tag), request);
	}
}

static bool
auth_process_input_user(struct auth_process *process, const char *args)
{
	struct login_auth_request *request;
	const char *const *list;
	unsigned int id;

	/* <id> <userid> [..] */

	list = t_strsplit(args, "\t");
	if (list[0] == NULL || list[1] == NULL) {
		i_error("BUG: Auth process %s sent corrupted USER line",
			dec2str(process->pid));
		return FALSE;
	}
	id = (unsigned int)strtoul(list[0], NULL, 10);

	request = hash_table_lookup(process->requests, POINTER_CAST(id));
	if (request == NULL) {
		i_error("BUG: Auth process %s sent unrequested reply with ID "
			"%u", dec2str(process->pid), id);
		return FALSE;
	}

	if (!auth_success_written) {
		int fd;

		fd = creat(AUTH_SUCCESS_PATH, 0666);
		if (fd == -1)
			i_error("creat(%s) failed: %m", AUTH_SUCCESS_PATH);
		else
			(void)close(fd);
		auth_success_written = TRUE;
	}

	auth_master_callback(list[1], list + 2, request);
	hash_table_remove(process->requests, POINTER_CAST(id));
	return TRUE;
}

static bool
auth_process_input_notfound(struct auth_process *process, const char *args)
{
	struct login_auth_request *request;
	unsigned int id;

	id = (unsigned int)strtoul(args, NULL, 10);

	request = hash_table_lookup(process->requests, POINTER_CAST(id));
	if (request == NULL) {
		i_error("BUG: Auth process %s sent unrequested reply with ID "
			"%u", dec2str(process->pid), id);
		return FALSE;
	}

	auth_master_callback(NULL, NULL, request);
	hash_table_remove(process->requests, POINTER_CAST(id));
	return TRUE;
}

static bool
auth_process_input_spid(struct auth_process *process, const char *args)
{
	unsigned int pid;

	if (process->initialized) {
		i_error("BUG: Authentication server re-handshaking");
		return FALSE;
	}

	pid = (unsigned int)strtoul(args, NULL, 10);
	if (pid == 0) {
		i_error("BUG: Authentication server said it's PID 0");
		return FALSE;
	}

	if (process->pid != 0 && process->pid != (pid_t)pid) {
		i_error("BUG: Authentication server sent invalid SPID "
			"(%u != %s)", pid, dec2str(process->pid));
		return FALSE;
	}

	process->pid = pid;
        process->initialized = TRUE;

	have_initialized_auth_processes = TRUE;
	return TRUE;
}

static bool
auth_process_input_fail(struct auth_process *process, const char *args)
{
	struct login_auth_request *request;
 	const char *error;
	unsigned int id;

	error = strchr(args, '\t');
	if (error != NULL)
		error++;

	id = (unsigned int)strtoul(args, NULL, 10);

	request = hash_table_lookup(process->requests, POINTER_CAST(id));
	if (request == NULL) {
		i_error("BUG: Auth process %s sent unrequested reply with ID "
			"%u", dec2str(process->pid), id);
		return FALSE;
	}

	auth_master_callback(NULL, NULL, request);
	hash_table_remove(process->requests, POINTER_CAST(id));
	return TRUE;
}

static bool
auth_process_input_line(struct auth_process *process, const char *line)
{
	if (strncmp(line, "USER\t", 5) == 0)
		return auth_process_input_user(process, line + 5);
	else if (strncmp(line, "NOTFOUND\t", 9) == 0)
		return auth_process_input_notfound(process, line + 9);
	else if (strncmp(line, "FAIL\t", 5) == 0)
		return auth_process_input_fail(process, line + 5);
	else if (strncmp(line, "SPID\t", 5) == 0)
		return auth_process_input_spid(process, line + 5);
	else
		return TRUE;
}

static void auth_process_input(struct auth_process *process)
{
	const char *line;
	bool ret;

	switch (i_stream_read(process->input)) {
	case 0:
		return;
	case -1:
		/* disconnected */
		auth_process_destroy(process);
		return;
	case -2:
		/* buffer full */
		i_error("BUG: Auth process %s sent us more than %d "
			"bytes of data", dec2str(process->pid),
			(int)MAX_INBUF_SIZE);
		auth_process_destroy(process);
		return;
	}

	if (!process->version_received) {
		line = i_stream_next_line(process->input);
		if (line == NULL)
			return;

		/* make sure the major version matches */
		if (strncmp(line, "VERSION\t", 8) != 0 ||
		    atoi(t_strcut(line + 8, '\t')) !=
		    AUTH_MASTER_PROTOCOL_MAJOR_VERSION) {
			i_error("Auth process %s not compatible with master "
				"process (mixed old and new binaries?)",
				dec2str(process->pid));
			auth_process_destroy(process);
			return;
		}
		process->version_received = TRUE;
	}

	while ((line = i_stream_next_line(process->input)) != NULL) {
		T_BEGIN {
			ret = auth_process_input_line(process, line);
		} T_END;
		if (!ret) {
			auth_process_destroy(process);
			break;
		}
	}
}

static void auth_worker_input(struct auth_process *p)
{
	int fd;

	fd = net_accept(p->worker_listen_fd, NULL, NULL);
	if (fd < 0) {
		if (fd == -2)
			i_error("accept(worker) failed: %m");
		return;
	}

	net_set_nonblock(fd, TRUE);
	fd_close_on_exec(fd, TRUE);

	create_auth_worker(p, fd);
}

static struct auth_process *
auth_process_new(pid_t pid, int fd, struct auth_process_group *group)
{
	struct auth_process *p;
	const char *path, *handshake;

	if (pid != 0)
		child_process_add(pid, &auth_child_process);

	p = i_new(struct auth_process, 1);
	p->group = group;
	p->pid = pid;
	p->fd = fd;
	p->io = io_add(fd, IO_READ, auth_process_input, p);
	p->input = i_stream_create_fd(fd, MAX_INBUF_SIZE, FALSE);
	p->output = o_stream_create_fd(fd, MAX_OUTBUF_SIZE, FALSE);
	p->requests = hash_table_create(default_pool, default_pool, 0,
					NULL, NULL);

	group->process_count++;

	path = t_strdup_printf("%s/auth-worker.%s",
			       *group->set->chroot != '\0' ?
			       group->set->chroot :
			       group->master_set->base_dir,
			       dec2str(pid));
	p->worker_listen_fd =
		unix_socket_create(path, 0600, group->set->uid,
				   group->set->gid, 128);
	if (p->worker_listen_fd == -1)
		i_fatal("Couldn't create auth worker listener");

	net_set_nonblock(p->worker_listen_fd, TRUE);
	fd_close_on_exec(p->worker_listen_fd, TRUE);
	p->worker_io = io_add(p->worker_listen_fd, IO_READ,
			      auth_worker_input, p);

	handshake = t_strdup_printf("VERSION\t%u\t%u\n",
				    AUTH_MASTER_PROTOCOL_MAJOR_VERSION,
				    AUTH_MASTER_PROTOCOL_MINOR_VERSION);
	(void)o_stream_send_str(p->output, handshake);

	p->next = group->processes;
	group->processes = p;
	return p;
}

static void auth_process_destroy(struct auth_process *p)
{
	struct hash_iterate_context *iter;
	void *key, *value;
	struct auth_process **pos;
	const char *path;

	if (!p->initialized && io_loop_is_running(ioloop) && !p->external) {
		/* log the process exit and kill ourself */
		child_processes_flush();
		log_deinit();
		i_fatal("Auth process died too early - shutting down");
	}

	for (pos = &p->group->processes; *pos != NULL; pos = &(*pos)->next) {
		if (*pos == p) {
			*pos = p->next;
			break;
		}
	}
	p->group->process_count--;

	path = t_strdup_printf("%s/auth-worker.%s",
			       *p->group->set->chroot != '\0' ?
			       p->group->set->chroot :
			       p->group->master_set->base_dir,
			       dec2str(p->pid));
	(void)unlink(path);

	io_remove(&p->worker_io);
	if (close(p->worker_listen_fd) < 0)
		i_error("close(worker_listen) failed: %m");

	iter = hash_table_iterate_init(p->requests);
	while (hash_table_iterate(iter, &key, &value))
		auth_master_callback(NULL, NULL, value);
	hash_table_iterate_deinit(&iter);
	hash_table_destroy(&p->requests);

	i_stream_destroy(&p->input);
	o_stream_destroy(&p->output);
	io_remove(&p->io);
	if (close(p->fd) < 0)
		i_error("close(auth) failed: %m");
	i_free(p);
}

static int connect_auth_socket(struct auth_process_group *group,
			       const char *path)
{
	struct auth_process *auth;
	int fd;

	fd = net_connect_unix(path);
	if (fd == -1) {
		i_error("net_connect_unix(%s) failed: %m", path);
		return -1;
	}

	net_set_nonblock(fd, TRUE);
	fd_close_on_exec(fd, TRUE);
	auth = auth_process_new(0, fd, group);
	auth->external = TRUE;
	return 0;
}

static void auth_set_environment(const struct master_settings *master_set,
				 const struct master_auth_settings *set)
{
	struct restrict_access_settings rset;

	master_settings_export_to_env(master_set);

	/* setup access environment */
	restrict_access_init(&rset);
	rset.system_groups_user = set->user;
	rset.uid = set->uid;
	rset.gid = set->gid;
	rset.chroot_dir = set->chroot;
	restrict_access_set_env(&rset);

	/* set other environment */
	env_put("DOVECOT_MASTER=1");
	env_put(t_strconcat("AUTH_NAME=", set->name, NULL));
	restrict_process_size(set->process_size, (unsigned int)-1);
}

static const struct master_auth_socket_settings *
get_connect_socket(const struct master_auth_settings *auth_set)
{
	struct master_auth_socket_settings *const *as;
	unsigned int count;

	if (!array_is_created(&auth_set->sockets))
		return NULL;

	as = array_get(&auth_set->sockets, &count);
	if (count > 0 && strcmp(as[0]->type, "connect") == 0)
		return as[0];
	else
		return NULL;
}

static int create_auth_process(struct auth_process_group *group)
{
	const struct master_auth_socket_settings *as;
	struct master_auth_socket_unix_settings *const *masters;
	const char *prefix, *executable;
	struct log_io *log;
	pid_t pid;
	unsigned int count;
	int fd[2], log_fd, i;

	/* see if this is a connect socket */
	as = get_connect_socket(group->set);
	if (as != NULL) {
		masters = array_get(&as->masters, &count);
		if (count > 0)
			return connect_auth_socket(group, masters[0]->path);
	}

	/* create communication to process with a socket pair */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
		i_error("socketpair() failed: %m");
		return -1;
	}

	log_fd = log_create_pipe(&log, 0);
	if (log_fd < 0)
		pid = -1;
	else {
		pid = fork();
		if (pid < 0)
			i_error("fork() failed: %m");
	}

	if (pid < 0) {
		(void)close(fd[0]);
		(void)close(fd[1]);
		(void)close(log_fd);
		return -1;
	}

	if (pid != 0) {
		/* master */
		prefix = t_strdup_printf("auth(%s): ", group->set->name);
		log_set_prefix(log, prefix);
		log_set_pid(log, pid);

		net_set_nonblock(fd[0], TRUE);
		fd_close_on_exec(fd[0], TRUE);
		auth_process_new(pid, fd[0], group);
		(void)close(fd[1]);
		(void)close(log_fd);
		return 0;
	}

	prefix = t_strdup_printf("master-auth(%s): ", group->set->name);
	log_set_prefix(log, prefix);

	/* move master communication handle to 0 */
	if (dup2(fd[1], 0) < 0)
		i_fatal("dup2(stdin) failed: %m");

	(void)close(fd[0]);
	(void)close(fd[1]);

	/* make sure we don't leak syslog fd. try to do it as late as possible,
	   but also before dup2()s in case syslog fd is one of them. */
	closelog();

	/* set stdout to /dev/null, so anything written into it gets ignored. */
	if (dup2(null_fd, 1) < 0)
		i_fatal("dup2(stdout) failed: %m");

	if (dup2(log_fd, 2) < 0)
		i_fatal("dup2(stderr) failed: %m");

	child_process_init_env(group->master_set);

	if (group->listen_fd != 3) {
		if (dup2(group->listen_fd, 3) < 0)
			i_fatal("dup2() failed: %m");
	}
	fd_close_on_exec(3, FALSE);

	for (i = 0; i <= 2; i++)
		fd_close_on_exec(i, FALSE);

        auth_set_environment(group->master_set, group->set);

	env_put(t_strdup_printf("AUTH_WORKER_PATH=%s/auth-worker.%s",
				*group->set->chroot != '\0' ? "" :
				group->master_set->base_dir,
				dec2str(getpid())));

	executable = group->set->executable;
	client_process_exec(executable, "");
	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", executable);
	return -1;
}

static int create_auth_worker(struct auth_process *process, int fd)
{
	struct log_io *log;
	const char *prefix, *executable;
	pid_t pid;
	int log_fd, i;

	log_fd = log_create_pipe(&log, 0);
	if (log_fd < 0)
		pid = -1;
	else {
		pid = fork();
		if (pid < 0)
			i_error("fork() failed: %m");
	}

	if (pid < 0) {
		(void)close(log_fd);
		return -1;
	}

	if (pid != 0) {
		/* master */
		child_process_add(pid, &auth_worker_child_process);
		prefix = t_strdup_printf("auth-worker(%s): ",
					 process->group->set->name);
		log_set_prefix(log, prefix);
		(void)close(fd);
		(void)close(log_fd);
		return 0;
	}

	prefix = t_strdup_printf("master-auth-worker(%s): ",
				 process->group->set->name);
	log_set_prefix(log, prefix);

	/* make sure we don't leak syslog fd. try to do it as late as possible,
	   but also before dup2()s in case syslog fd is one of them. */
	closelog();

	/* set stdin and stdout to /dev/null, so anything written into it
	   gets ignored. */
	if (dup2(null_fd, 0) < 0)
		i_fatal("dup2(stdin) failed: %m");
	if (dup2(null_fd, 1) < 0)
		i_fatal("dup2(stdout) failed: %m");

	if (dup2(log_fd, 2) < 0)
		i_fatal("dup2(stderr) failed: %m");

	if (dup2(fd, 4) < 0)
		i_fatal("dup2(4) failed: %m");

	for (i = 0; i <= 2; i++)
		fd_close_on_exec(i, FALSE);
	fd_close_on_exec(4, FALSE);

	child_process_init_env(process->group->master_set);
        auth_set_environment(process->group->master_set, process->group->set);

	executable = t_strconcat(process->group->set->executable, " -w", NULL);
	client_process_exec(executable, "");
	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m", executable);
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

static void auth_process_group_create(struct master_settings *set,
				      struct master_auth_settings *auth_set)
{
	struct auth_process_group *group;
	const char *path;

	group = i_new(struct auth_process_group, 1);
	group->master_set = set;
	group->set = auth_set;

	group->next = process_groups;
	process_groups = group;

	if (get_connect_socket(auth_set) != NULL)
		return;

	path = t_strconcat(set->login_dir, "/", auth_set->name, NULL);
	group->listen_fd = unix_socket_create(path, 0660, master_uid,
					      set->server->login_gid, 128);
	if (group->listen_fd == -1)
		i_fatal("Couldn't create auth process listener");

	net_set_nonblock(group->listen_fd, TRUE);
	fd_close_on_exec(group->listen_fd, TRUE);
}

static void auth_process_group_destroy(struct auth_process_group *group)
{
	struct auth_process *next;
	const char *path;

	while (group->processes != NULL) {
		next = group->processes->next;
		auth_process_destroy(group->processes);
                group->processes = next;
	}

	path = t_strconcat(group->master_set->login_dir, "/",
			   group->set->name, NULL);
	(void)unlink(path);

	if (close(group->listen_fd) < 0)
		i_error("close(%s) failed: %m", path);
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

	have_initialized_auth_processes = FALSE;
}

static void auth_process_groups_create(struct master_settings *set)
{
	struct master_auth_settings *const *auth_sets;
	unsigned int i, count;

	auth_sets = array_get(&set->auths, &count);
	for (i = 0; i < count; i++)
		auth_process_group_create(set, auth_sets[i]);
}

static void auth_processes_stall(void)
{
	if (auth_stalled)
		return;

	i_error("Temporary failure in creating authentication processes, "
		"slowing down for now");
	auth_stalled = TRUE;

	timeout_remove(&to);
	to = timeout_add(60*1000, auth_processes_start_missing, NULL);
}

static void
auth_processes_start_missing(void *context ATTR_UNUSED)
{
	struct auth_process_group *group;
	unsigned int count;

	if (process_groups == NULL) {
		/* first time here, create the groups */
		auth_process_groups_create(master_set->defaults);
	}

	for (group = process_groups; group != NULL; group = group->next) {
		count = group->process_count;
		for (; count < group->set->count; count++) {
			if (create_auth_process(group) < 0) {
				auth_processes_stall();
				return;
			}
		}
	}

	if (auth_stalled) {
		/* processes were created successfully */
		i_info("Created authentication processes successfully, "
		       "unstalling");

		auth_stalled = FALSE;
		timeout_remove(&to);
		to = timeout_add(1000, auth_processes_start_missing, NULL);
	}
}

void auth_processes_init(void)
{
	process_groups = NULL;
	to = timeout_add(1000, auth_processes_start_missing, NULL);

	auth_processes_start_missing(NULL);
}

void auth_processes_deinit(void)
{
	timeout_remove(&to);
	auth_processes_destroy_all();
}
