/* Copyright (c) 2002-2007 Dovecot authors, see the included COPYING file */

#include "common.h"
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
#include <pwd.h>
#include <syslog.h>

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
	{ PROCESS_TYPE_AUTH };
static struct child_process auth_worker_child_process =
	{ PROCESS_TYPE_AUTH_WORKER };

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
		hash_insert(process->requests, POINTER_CAST(auth_tag), request);
	}
	t_pop();
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

	request = hash_lookup(process->requests, POINTER_CAST(id));
	if (request == NULL) {
		i_error("BUG: Auth process %s sent unrequested reply with ID "
			"%u", dec2str(process->pid), id);
		return FALSE;
	}

	auth_master_callback(list[1], list + 2, request);
	hash_remove(process->requests, POINTER_CAST(id));
	return TRUE;
}

static bool
auth_process_input_notfound(struct auth_process *process, const char *args)
{
	struct login_auth_request *request;
	unsigned int id;

	id = (unsigned int)strtoul(args, NULL, 10);

	request = hash_lookup(process->requests, POINTER_CAST(id));
	if (request == NULL) {
		i_error("BUG: Auth process %s sent unrequested reply with ID "
			"%u", dec2str(process->pid), id);
		return FALSE;
	}

	auth_master_callback(NULL, NULL, request);
	hash_remove(process->requests, POINTER_CAST(id));
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

	request = hash_lookup(process->requests, POINTER_CAST(id));
	if (request == NULL) {
		i_error("BUG: Auth process %s sent unrequested reply with ID "
			"%u", dec2str(process->pid), id);
		return FALSE;
	}

	auth_master_callback(NULL, NULL, request);
	hash_remove(process->requests, POINTER_CAST(id));
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
	p->requests = hash_create(default_pool, default_pool, 0, NULL, NULL);

	group->process_count++;

	path = t_strdup_printf("%s/auth-worker.%s",
			       *group->set->chroot != '\0' ?
			       group->set->chroot :
			       group->set->parent->defaults->base_dir,
			       dec2str(pid));
	p->worker_listen_fd =
		unix_socket_create(path, 0600, group->set->uid,
				   group->set->gid, 16);
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

	path = t_strdup_printf("%s/auth-worker.%s",
			       *p->group->set->chroot != '\0' ?
			       p->group->set->chroot :
			       p->group->set->parent->defaults->base_dir,
			       dec2str(p->pid));
	(void)unlink(path);

	io_remove(&p->worker_io);
	if (close(p->worker_listen_fd) < 0)
		i_error("close(worker_listen) failed: %m");

	iter = hash_iterate_init(p->requests);
	while (hash_iterate(iter, &key, &value))
		auth_master_callback(NULL, NULL, value);
	hash_iterate_deinit(&iter);
	hash_destroy(&p->requests);

	i_stream_destroy(&p->input);
	o_stream_destroy(&p->output);
	io_remove(&p->io);
	if (close(p->fd) < 0)
		i_error("close(auth) failed: %m");
	i_free(p);
}

static void
socket_settings_env_put(const char *env_base, struct socket_settings *set)
{
	if (!set->used)
		return;

	env_put(t_strdup_printf("%s=%s", env_base, set->path));
	if (set->mode != 0)
		env_put(t_strdup_printf("%s_MODE=%o", env_base, set->mode));
	if (*set->user != '\0')
		env_put(t_strdup_printf("%s_USER=%s", env_base, set->user));
	if (*set->group != '\0')
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

static void auth_set_environment(struct auth_settings *set)
{
	struct auth_socket_settings *as;
	struct auth_passdb_settings *ap;
	struct auth_userdb_settings *au;
	const char *str;
	int i;

	/* setup access environment */
	restrict_access_set_env(set->user, set->uid, set->gid, set->chroot,
				0, 0, NULL);

	/* set other environment */
	env_put("DOVECOT_MASTER=1");
	env_put(t_strconcat("AUTH_NAME=", set->name, NULL));
	env_put(t_strconcat("MECHANISMS=", set->mechanisms, NULL));
	env_put(t_strconcat("REALMS=", set->realms, NULL));
	env_put(t_strconcat("DEFAULT_REALM=", set->default_realm, NULL));
	env_put(t_strconcat("USERNAME_CHARS=", set->username_chars, NULL));
	env_put(t_strconcat("ANONYMOUS_USERNAME=",
			    set->anonymous_username, NULL));
	env_put(t_strconcat("USERNAME_TRANSLATION=",
			    set->username_translation, NULL));
	env_put(t_strconcat("USERNAME_FORMAT=", set->username_format, NULL));
	env_put(t_strconcat("MASTER_USER_SEPARATOR=",
			    set->master_user_separator, NULL));
	env_put(t_strdup_printf("CACHE_SIZE=%u", set->cache_size));
	env_put(t_strdup_printf("CACHE_TTL=%u", set->cache_ttl));
	env_put(t_strdup_printf("CACHE_NEGATIVE_TTL=%u",
				set->cache_negative_ttl));

	for (ap = set->passdbs, i = 1; ap != NULL; ap = ap->next, i++) {
		env_put(t_strdup_printf("PASSDB_%u_DRIVER=%s", i, ap->driver));
		if (ap->args != NULL) {
			env_put(t_strdup_printf("PASSDB_%u_ARGS=%s",
						i, ap->args));
		}
		if (ap->deny)
			env_put(t_strdup_printf("PASSDB_%u_DENY=1", i));
                if (ap->pass)
                        env_put(t_strdup_printf("PASSDB_%u_PASS=1", i));
		if (ap->master)
                        env_put(t_strdup_printf("PASSDB_%u_MASTER=1", i));
	}
	for (au = set->userdbs, i = 1; au != NULL; au = au->next, i++) {
		env_put(t_strdup_printf("USERDB_%u_DRIVER=%s", i, au->driver));
		if (au->args != NULL) {
			env_put(t_strdup_printf("USERDB_%u_ARGS=%s",
						i, au->args));
		}
	}

	for (as = set->sockets, i = 1; as != NULL; as = as->next, i++) {
		if (strcmp(as->type, "listen") != 0)
			continue;

		str = t_strdup_printf("AUTH_%u", i);
		socket_settings_env_put(str, &as->client);
		socket_settings_env_put(t_strconcat(str, "_MASTER", NULL),
					&as->master);
	}

	if (set->verbose)
		env_put("VERBOSE=1");
	if (set->debug)
		env_put("VERBOSE_DEBUG=1");
	if (set->debug_passwords)
		env_put("VERBOSE_DEBUG_PASSWORDS=1");
	if (set->ssl_require_client_cert)
		env_put("SSL_REQUIRE_CLIENT_CERT=1");
	if (set->ssl_username_from_cert)
		env_put("SSL_USERNAME_FROM_CERT=1");
	if (set->ntlm_use_winbind)
		env_put("NTLM_USE_WINBIND=1");
	if (*set->krb5_keytab != '\0') {
		/* Environment used by Kerberos 5 library directly */
		env_put(t_strconcat("KRB5_KTNAME=", set->krb5_keytab, NULL));
	}
	if (*set->gssapi_hostname != '\0') {
		env_put(t_strconcat("GSSAPI_HOSTNAME=",
				    set->gssapi_hostname, NULL));
	}
	env_put(t_strconcat("WINBIND_HELPER_PATH=",
			    set->winbind_helper_path, NULL));

	restrict_process_size(set->process_size, (unsigned int)-1);
}

static int create_auth_process(struct auth_process_group *group)
{
	struct auth_socket_settings *as;
	const char *prefix, *executable;
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

	if (group->listen_fd != 3) {
		if (dup2(group->listen_fd, 3) < 0)
			i_fatal("dup2() failed: %m");
	}
	fd_close_on_exec(3, FALSE);

	for (i = 0; i <= 2; i++)
		fd_close_on_exec(i, FALSE);

        auth_set_environment(group->set);

	env_put(t_strdup_printf("AUTH_WORKER_PATH=%s/auth-worker.%s",
				*group->set->chroot != '\0' ? "" :
				group->set->parent->defaults->base_dir,
				dec2str(getpid())));
	env_put(t_strdup_printf("AUTH_WORKER_MAX_COUNT=%u",
				group->set->worker_max_count));
	env_put(t_strdup_printf("AUTH_WORKER_MAX_REQUEST_COUNT=%u",
				group->set->worker_max_request_count));

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

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

	child_process_init_env();
        auth_set_environment(process->group->set);

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

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

static void auth_process_group_create(struct auth_settings *auth_set)
{
	struct auth_process_group *group;
	const char *path;

	group = i_new(struct auth_process_group, 1);
	group->set = auth_set;

	group->next = process_groups;
	process_groups = group;

	if (auth_set->sockets != NULL &&
	    strcmp(auth_set->sockets->type, "connect") == 0)
		return;

	path = t_strconcat(auth_set->parent->defaults->login_dir, "/",
			   auth_set->name, NULL);
	group->listen_fd = unix_socket_create(path, 0660, master_uid,
					      auth_set->parent->login_gid, 16);
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

	path = t_strconcat(group->set->parent->defaults->login_dir, "/",
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
		auth_process_groups_create(settings_root);
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
