/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "ioloop.h"
#include "env-util.h"
#include "fd-close-on-exec.h"
#include "network.h"
#include "istream.h"
#include "ostream.h"
#include "str.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "auth-process.h"
#include "../auth/auth-master-interface.h"
#include "log.h"

#include <stdlib.h>
#include <unistd.h>
#include <pwd.h>
#include <syslog.h>
#include <sys/stat.h>

#define MAX_INBUF_SIZE 8192
#define MAX_OUTBUF_SIZE 65536

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

	struct hash_table *requests;

	unsigned int external:1;
	unsigned int version_received:1;
	unsigned int initialized:1;
	unsigned int in_auth_reply:1;
};

static struct timeout *to;
static unsigned int auth_tag;
static struct auth_process_group *process_groups;

static void auth_process_destroy(struct auth_process *p);

void auth_process_request(struct auth_process *process, unsigned int login_pid,
			  unsigned int login_id, void *context)
{
	string_t *str;
	ssize_t ret;

	t_push();
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
		hash_insert(process->requests, POINTER_CAST(auth_tag), context);
	}
	t_pop();
}

static int
auth_process_input_user(struct auth_process *process, const char *args)
{
	void *context;
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

	context = hash_lookup(process->requests, POINTER_CAST(id));
	if (context == NULL) {
		i_error("BUG: Auth process %s sent unrequested reply with ID "
			"%u", dec2str(process->pid), id);
		return FALSE;
	}

	auth_master_callback(list[1], list + 2, context);
	hash_remove(process->requests, POINTER_CAST(id));
	return TRUE;
}

static int
auth_process_input_notfound(struct auth_process *process, const char *args)
{
	void *context;
	unsigned int id;

	id = (unsigned int)strtoul(args, NULL, 10);

	context = hash_lookup(process->requests, POINTER_CAST(id));
	if (context == NULL) {
		i_error("BUG: Auth process %s sent unrequested reply with ID "
			"%u", dec2str(process->pid), id);
		return FALSE;
	}

	auth_master_callback(NULL, NULL, context);
	hash_remove(process->requests, POINTER_CAST(id));
	return TRUE;
}

static int
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
	return TRUE;
}

static int
auth_process_input_fail(struct auth_process *process, const char *args)
{
	void *context;
 	const char *error;
	unsigned int id;

	error = strchr(args, '\t');
	if (error != NULL)
		error++;

	id = (unsigned int)strtoul(args, NULL, 10);

	context = hash_lookup(process->requests, POINTER_CAST(id));
	if (context == NULL) {
		i_error("BUG: Auth process %s sent unrequested reply with ID "
			"%u", dec2str(process->pid), id);
		return FALSE;
	}

	auth_master_callback(NULL, NULL, context);
	hash_remove(process->requests, POINTER_CAST(id));
	return TRUE;
}

static void auth_process_input(void *context)
{
	struct auth_process *process = context;
	const char *line;
	int ret;

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
		    atoi(t_strcut(line + 8, '.')) !=
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
		t_push();
		if (strncmp(line, "USER\t", 5) == 0)
			ret = auth_process_input_user(process, line + 5);
		else if (strncmp(line, "NOTFOUND\t", 9) == 0)
			ret = auth_process_input_notfound(process, line + 9);
		else if (strncmp(line, "FAIL\t", 5) == 0)
			ret = auth_process_input_fail(process, line + 5);
		else if (strncmp(line, "SPID\t", 5) == 0)
			ret = auth_process_input_spid(process, line + 5);
		else
			ret = TRUE;
		t_pop();

		if (!ret) {
			auth_process_destroy(process);
			break;
		}
	}
}

static struct auth_process *
auth_process_new(pid_t pid, int fd, struct auth_process_group *group)
{
	struct auth_process *p;
	const char *handshake;

	if (pid != 0)
		PID_ADD_PROCESS_TYPE(pid, PROCESS_TYPE_AUTH);

	p = i_new(struct auth_process, 1);
	p->group = group;
	p->pid = pid;
	p->fd = fd;
	p->io = io_add(fd, IO_READ, auth_process_input, p);
	p->input = i_stream_create_file(fd, default_pool,
					MAX_INBUF_SIZE, FALSE);
	p->output = o_stream_create_file(fd, default_pool, MAX_OUTBUF_SIZE,
					 FALSE);
	p->requests = hash_create(default_pool, default_pool, 0, NULL, NULL);

	handshake = t_strdup_printf("VERSION\t%u.%u\n",
				    AUTH_MASTER_PROTOCOL_MAJOR_VERSION,
				    AUTH_MASTER_PROTOCOL_MINOR_VERSION);
	(void)o_stream_send_str(p->output, handshake);

	p->next = group->processes;
	group->processes = p;
	group->process_count++;
	return p;
}

static void auth_process_destroy(struct auth_process *p)
{
	struct hash_iterate_context *iter;
	void *key, *value;
	struct auth_process **pos;

	if (!p->initialized && io_loop_is_running(ioloop) && !p->external) {
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

	iter = hash_iterate_init(p->requests);
	while (hash_iterate(iter, &key, &value))
		auth_master_callback(NULL, NULL, value);
	hash_iterate_deinit(iter);
	hash_destroy(p->requests);

	i_stream_unref(p->input);
	o_stream_unref(p->output);
	io_remove(p->io);
	if (close(p->fd) < 0)
		i_error("close(auth) failed: %m");
	i_free(p);
}

static void
socket_settings_env_put(const char *env_base, struct socket_settings *set)
{
	if (env_base == NULL)
		return;

	env_put(t_strdup_printf("%s_PATH=%s", env_base, set->path));
	if (set->mode != 0)
		env_put(t_strdup_printf("%s_MODE=%u", env_base, set->mode));
	if (set->user != NULL)
		env_put(t_strdup_printf("%s_USER=%s", env_base, set->user));
	if (set->group != NULL)
		env_put(t_strdup_printf("%s_GROUP=%s", env_base, set->group));
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

static int create_auth_process(struct auth_process_group *group)
{
	static char *argv[] = { NULL, NULL };
	struct auth_socket_settings *as;
	const char *prefix, *str;
	struct log_io *log;
	pid_t pid;
	int fd[2], log_fd, i;

	/* see if this is a connect socket */
	as = group->set->sockets;
	if (as != NULL && strcmp(as->type, "connect") == 0)
		return connect_auth_socket(group, as->master.path);

	/* create communication to process with a socket pair */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
		i_error("socketpair() failed: %m");
		return -1;
	}

	log_fd = log_create_pipe(&log);
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

	/* set stdout to /dev/null, so anything written into it gets ignored. */
	if (dup2(null_fd, 1) < 0)
		i_fatal("dup2(stdout) failed: %m");

	if (dup2(log_fd, 2) < 0)
		i_fatal("dup2(stderr) failed: %m");

	child_process_init_env();

	/* move login communication handle to 3. do it last so we can be
	   sure it's not closed afterwards. */
	if (group->listen_fd != 3) {
		if (dup2(group->listen_fd, 3) < 0)
			i_fatal("dup2() failed: %m");
	}

	for (i = 0; i <= 3; i++)
		fd_close_on_exec(i, FALSE);

	/* setup access environment */
	restrict_access_set_env(group->set->user, group->set->uid,
				group->set->gid, group->set->chroot,
				0, 0, NULL);

	/* set other environment */
	env_put(t_strconcat("AUTH_PROCESS=", dec2str(getpid()), NULL));
	env_put(t_strconcat("MECHANISMS=", group->set->mechanisms, NULL));
	env_put(t_strconcat("REALMS=", group->set->realms, NULL));
	env_put(t_strconcat("DEFAULT_REALM=", group->set->default_realm, NULL));
	env_put(t_strconcat("USERDB=", group->set->userdb, NULL));
	env_put(t_strconcat("PASSDB=", group->set->passdb, NULL));
	env_put(t_strconcat("USERNAME_CHARS=", group->set->username_chars, NULL));
	env_put(t_strconcat("USERNAME_TRANSLATION=",
			    group->set->username_translation, NULL));
	env_put(t_strconcat("ANONYMOUS_USERNAME=",
			    group->set->anonymous_username, NULL));
	env_put(t_strdup_printf("CACHE_SIZE=%u", group->set->cache_size));
	env_put(t_strdup_printf("CACHE_TTL=%u", group->set->cache_ttl));

	for (as = group->set->sockets, i = 1; as != NULL; as = as->next, i++) {
		if (strcmp(as->type, "listen") != 0)
			continue;

		str = t_strdup_printf("AUTH_%u", i);
		socket_settings_env_put(str, &as->client);
		socket_settings_env_put(t_strconcat(str, "_MASTER", NULL),
					&as->master);
	}

	if (group->set->verbose)
		env_put("VERBOSE=1");
	if (group->set->debug)
		env_put("VERBOSE_DEBUG=1");
	if (group->set->ssl_require_client_cert)
		env_put("SSL_REQUIRE_CLIENT_CERT=1");

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
	mode_t old_umask;

	group = i_new(struct auth_process_group, 1);
	group->set = auth_set;

	group->next = process_groups;
	process_groups = group;

	if (auth_set->sockets != NULL &&
	    strcmp(auth_set->sockets->type, "connect") == 0)
		return;

	/* create socket for listening auth requests from login */
	path = t_strconcat(auth_set->parent->defaults->login_dir, "/",
			   auth_set->name, NULL);
	(void)unlink(path);

	old_umask = umask(0117); /* we want 0660 mode for the socket */
	group->listen_fd = net_listen_unix(path);
	umask(old_umask);

	if (group->listen_fd < 0)
		i_fatal("Can't listen in UNIX socket %s: %m", path);
	net_set_nonblock(group->listen_fd, TRUE);
	fd_close_on_exec(group->listen_fd, TRUE);

	/* set correct permissions */
	if (chown(path, master_uid, auth_set->parent->login_gid) < 0) {
		i_fatal("login: chown(%s, %s, %s) failed: %m",
			path, dec2str(master_uid),
			dec2str(auth_set->parent->login_gid));
	}
}

static void auth_process_group_destroy(struct auth_process_group *group)
{
	struct auth_process *next;

	while (group->processes != NULL) {
		next = group->processes->next;
		auth_process_destroy(group->processes);
                group->processes = next;
	}

	(void)unlink(t_strconcat(group->set->parent->defaults->login_dir, "/",
				 group->set->name, NULL));

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

static void auth_process_groups_create(struct server_settings *server)
{
	struct auth_settings *auth_set;

	while (server != NULL) {
		auth_set = server->auths;
		for (; auth_set != NULL; auth_set = auth_set->next)
			auth_process_group_create(auth_set);

                server = server->next;
	}
}

static void
auth_processes_start_missing(void *context __attr_unused__)
{
	struct auth_process_group *group;
	unsigned int count;

	if (process_groups == NULL) {
		/* first time here, create the groups */
		auth_process_groups_create(settings_root);
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
