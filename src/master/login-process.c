/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "ioloop.h"
#include "hash.h"
#include "network.h"
#include "ostream.h"
#include "fdpass.h"
#include "fd-close-on-exec.h"
#include "env-util.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "dup2-array.h"
#include "login-process.h"
#include "auth-process.h"
#include "mail-process.h"
#include "master-login-interface.h"
#include "log.h"
#include "ssl-init.h"

#include <unistd.h>
#include <syslog.h>
#include <sys/stat.h>

struct login_process {
	struct child_process process;

	struct login_group *group;
	struct login_process *prev_prelogin, *next_prelogin;
	int refcount;

	pid_t pid;
	int fd;
	struct io *io;
	struct ostream *output;
	enum master_login_state state;

	unsigned int initialized:1;
	unsigned int destroyed:1;
	unsigned int inetd_child:1;
};

struct login_auth_request {
	struct login_process *process;
	unsigned int tag;
	unsigned int login_tag;

	struct mail_login_request mail_request;
	unsigned char data[];
};

static unsigned int auth_id_counter, login_pid_counter;
static struct timeout *to;
static struct io *io_listen;
static bool logins_stalled = FALSE;

static struct login_group *login_groups;

static void login_processes_stall(void);
static void login_process_destroy(struct login_process *p);
static void login_process_unref(struct login_process *p);
static bool login_process_init_group(struct login_process *p);
static void login_processes_start_missing(void *context);

static void login_group_create(struct settings *set)
{
	struct login_group *group;

	group = i_new(struct login_group, 1);
	group->refcount = 1;
	group->set = set;
	group->mail_process_type = set->protocol == MAIL_PROTOCOL_IMAP ?
		PROCESS_TYPE_IMAP : PROCESS_TYPE_POP3;

	group->next = login_groups;
	login_groups = group;
}

static void login_group_unref(struct login_group *group)
{
	i_assert(group->refcount > 0);

	if (--group->refcount > 0)
		return;

	i_free(group);
}

void auth_master_callback(const char *user, const char *const *args,
			  struct login_auth_request *request)
{
	struct master_login_reply master_reply;
	ssize_t ret;

	memset(&master_reply, 0, sizeof(master_reply));
	if (user == NULL)
		master_reply.status = MASTER_LOGIN_STATUS_INTERNAL_ERROR;
	else T_BEGIN {
		struct login_group *group = request->process->group;

		master_reply.status =
			create_mail_process(group->mail_process_type,
					    group->set, &request->mail_request,
					    user, args, request->data, FALSE);
	} T_END;

	/* reply to login */
	master_reply.tag = request->login_tag;

	ret = o_stream_send(request->process->output, &master_reply,
			    sizeof(master_reply));
	if (ret != sizeof(master_reply)) {
		if (ret >= 0) {
			i_warning("Login process %s transmit buffer full, "
				  "killing..", dec2str(request->process->pid));
		}
		login_process_destroy(request->process);
	}

	if (close(request->mail_request.fd) < 0)
		i_error("close(mail client) failed: %m");
	login_process_unref(request->process);
	i_free(request);
}

static void process_remove_from_prelogin_lists(struct login_process *p)
{
	if (p->state != LOGIN_STATE_FULL_PRELOGINS)
		return;

	if (p->prev_prelogin == NULL)
		p->group->oldest_prelogin_process = p->next_prelogin;
	else
		p->prev_prelogin->next_prelogin = p->next_prelogin;

	if (p->next_prelogin == NULL)
		p->group->newest_prelogin_process = p->prev_prelogin;
	else
		p->next_prelogin->prev_prelogin = p->prev_prelogin;

	p->prev_prelogin = p->next_prelogin = NULL;
}

static void process_mark_nonlistening(struct login_process *p,
				      enum master_login_state new_state)
{
	if (p->group == NULL)
		return;

	if (p->state == LOGIN_STATE_LISTENING)
		p->group->listening_processes--;

	if (new_state == LOGIN_STATE_FULL_PRELOGINS) {
		/* add to prelogin list */
		i_assert(p->state != new_state);

		p->prev_prelogin = p->group->newest_prelogin_process;
		if (p->group->newest_prelogin_process == NULL)
			p->group->oldest_prelogin_process = p;
		else
			p->group->newest_prelogin_process->next_prelogin = p;
		p->group->newest_prelogin_process = p;
	} else {
		process_remove_from_prelogin_lists(p);
	}
}

static void process_mark_listening(struct login_process *p)
{
	if (p->group == NULL)
		return;

	if (p->state != LOGIN_STATE_LISTENING)
		p->group->listening_processes++;

	process_remove_from_prelogin_lists(p);
}

static void login_process_set_initialized(struct login_process *p)
{
	p->initialized = TRUE;

	if (logins_stalled) {
		/* processes were created successfully */
		i_info("Created login processes successfully, unstalling");

		logins_stalled = FALSE;
		timeout_remove(&to);
		to = timeout_add(1000, login_processes_start_missing, NULL);
	}
}

static void
login_process_set_state(struct login_process *p, enum master_login_state state)
{
	if (state == p->state || state > LOGIN_STATE_COUNT ||
	    (state < p->state && p->group->set->login_process_per_connection)) {
		i_error("login: tried to change state %d -> %d "
			"(if you can't login at all, see src/lib/fdpass.c)",
			p->state, state);
		login_process_destroy(p);
		return;
	}

	if (state == LOGIN_STATE_LISTENING) {
		process_mark_listening(p);
	} else {
		process_mark_nonlistening(p, state);
	}

	p->state = state;
}

static void login_process_groups_create(void)
{
	struct server_settings *server;

	for (server = settings_root; server != NULL; server = server->next) {
		if (server->imap != NULL)
			login_group_create(server->imap);
		if (server->pop3 != NULL)
			login_group_create(server->pop3);
	}
}

static struct login_group *
login_group_process_find(const char *name, enum mail_protocol protocol)
{
	struct login_group *group;

	if (login_groups == NULL)
                login_process_groups_create();

	for (group = login_groups; group != NULL; group = group->next) {
		if (strcmp(group->set->server->name, name) == 0 &&
		    group->set->protocol == protocol)
			return group;
	}

	return NULL;
}

static bool login_process_read_group(struct login_process *p)
{
	struct login_group *group;
	const char *name, *proto;
	unsigned char buf[256];
	enum mail_protocol protocol;
	unsigned int len;
	ssize_t ret;

	/* read length */
	ret = read(p->fd, buf, 1);
	if (ret != 1)
		len = 0;
	else {
		len = buf[0];
		if (len >= sizeof(buf)) {
			i_error("login: Server name length too large");
			return FALSE;
		}

		ret = read(p->fd, buf, len);
	}

	if (ret < 0)
		i_error("login: read() failed: %m");
	else if (len == 0 || (size_t)ret != len)
		i_error("login: Server name wasn't sent");
	else {
		name = t_strndup(buf, len);
		proto = strchr(name, '/');
		if (proto == NULL) {
			proto = name;
			name = "default";
		} else {
			name = t_strdup_until(name, proto++);
		}

		if (strcmp(proto, "imap") == 0)
			protocol = MAIL_PROTOCOL_IMAP;
		else if (strcmp(proto, "pop3") == 0)
			protocol = MAIL_PROTOCOL_POP3;
		else {
			i_error("login: Unknown protocol '%s'", proto);
			return FALSE;
		}

		group = login_group_process_find(name, protocol);
		if (group == NULL) {
			i_error("login: Unknown server name '%s'", name);
			return FALSE;
		}

		p->group = group;
		return login_process_init_group(p);
	}
	return FALSE;
}

static int
login_read_request(struct login_process *p, struct master_login_request *req,
		   unsigned char data[MASTER_LOGIN_MAX_DATA_SIZE],
		   int *client_fd_r)
{
	struct stat st;
	ssize_t ret;

	*client_fd_r = -1;

	ret = fd_read(p->fd, req, sizeof(*req), client_fd_r);
	if (ret >= (ssize_t)sizeof(req->version) &&
	    req->version != MASTER_LOGIN_PROTOCOL_VERSION) {
		i_error("login: Protocol version mismatch "
			"(mixed old and new binaries?)");
		return -1;
	}

	if (ret != sizeof(*req)) {
		if (ret == 0) {
			/* disconnected, ie. the login process died */
		} else if (ret > 0) {
			/* request wasn't fully read */
			i_error("login: fd_read() returned partial %d",
				(int)ret);
		} else {
			if (errno == EAGAIN)
				return 0;

			i_error("login: fd_read() failed: %m");
		}
		return -1;
	}

	if (req->ino == (ino_t)-1) {
		if (*client_fd_r != -1) {
			i_error("login: Notification request sent "
				"a file descriptor");
			return -1;
		}
		return 1;
	}
	if (req->data_size != 0) {
		if (req->data_size > MASTER_LOGIN_MAX_DATA_SIZE) {
			i_error("login: Too large data_size sent");
			return -1;
		}
		/* @UNSAFE */
		ret = read(p->fd, data, req->data_size);
		if (ret != req->data_size) {
			if (ret == 0) {
				/* disconnected */
			} else if (ret > 0) {
				/* request wasn't fully read */
				i_error("login: Data read partially %d/%u",
					(int)ret, req->data_size);
			} else {
				i_error("login: read(data) failed: %m");
			}
			return -1;
		}
	}

	if (*client_fd_r == -1) {
		i_error("login: Login request missing a file descriptor");
		return -1;
	}

	if (fstat(*client_fd_r, &st) < 0) {
		i_error("login: fstat(mail client) failed: %m");
		return -1;
	}
	if (st.st_ino != req->ino) {
		i_error("login: Login request inode mismatch: %s != %s",
			dec2str(st.st_ino), dec2str(req->ino));
		return -1;
	}
	return 1;
}

static void login_process_input(struct login_process *p)
{
	struct auth_process *auth_process;
	struct login_auth_request *authreq;
	struct master_login_request req;
	unsigned char data[MASTER_LOGIN_MAX_DATA_SIZE];
	int client_fd;
	ssize_t ret;

	if (p->group == NULL) {
		/* we want to read the group */
		if (!login_process_read_group(p))
			login_process_destroy(p);
		return;
	}

	ret = login_read_request(p, &req, data, &client_fd);
	if (ret == 0)
		return;
	if (ret < 0) {
		if (client_fd != -1) {
			if (close(client_fd) < 0)
				i_error("login: close(mail client) failed: %m");
		}
		login_process_destroy(p);
		return;
	}

	if (req.ino == (ino_t)-1) {
		/* state notification */
		enum master_login_state state = req.tag;

		if (!p->initialized) {
			/* initialization notify */
			login_process_set_initialized(p);
		} else {
			/* change "listening for new connections" status */
			login_process_set_state(p, state);
		}
		return;
	}

	if (!p->initialized) {
		i_error("login: trying to log in before initialization");
		login_process_destroy(p);
		return;
	}

	fd_close_on_exec(client_fd, TRUE);

	/* ask the cookie from the auth process */
	authreq = i_malloc(sizeof(*authreq) + req.data_size);
	p->refcount++;
	authreq->process = p;
	authreq->tag = ++auth_id_counter;
	authreq->login_tag = req.tag;
	authreq->mail_request.fd = client_fd;
	authreq->mail_request.local_ip = req.local_ip;
	authreq->mail_request.remote_ip = req.remote_ip;
	authreq->mail_request.cmd_tag_size = req.cmd_tag_size;
	authreq->mail_request.data_size = req.data_size;
	memcpy(authreq->data, data, req.data_size);

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
login_process_new(struct login_group *group, pid_t pid, int fd,
		  bool inetd_child)
{
	struct login_process *p;

	i_assert(pid != 0);

	p = i_new(struct login_process, 1);
	p->process.type = PROCESS_TYPE_LOGIN;
	p->group = group;
	p->refcount = 2; /* once for fd close, another for process exit */
	p->pid = pid;
	p->fd = fd;
	p->inetd_child = inetd_child;
	p->io = io_add(fd, IO_READ, login_process_input, p);
	p->output = o_stream_create_fd(fd, sizeof(struct master_login_reply)*10,
				       FALSE);
	if (!inetd_child)
		child_process_add(pid, &p->process);

	p->state = LOGIN_STATE_LISTENING;

	if (p->group != NULL) {
		p->group->refcount++;
		p->group->processes++;
		p->group->listening_processes++;
	}
	return p;
}

static void login_process_exited(struct login_process *p)
{
	if (p->group != NULL)
		p->group->processes--;

	login_process_unref(p);
}

static void login_process_destroy(struct login_process *p)
{
	if (p->destroyed)
		return;
	p->destroyed = TRUE;

	if (!p->initialized)
		login_processes_stall();

	o_stream_close(p->output);
	io_remove(&p->io);
	if (close(p->fd) < 0)
		i_error("close(login) failed: %m");

	process_mark_nonlistening(p, LOGIN_STATE_FULL_LOGINS);

	if (p->inetd_child)
		login_process_exited(p);
	login_process_unref(p);
}

static void login_process_unref(struct login_process *p)
{
	i_assert(p->refcount > 0);
	if (--p->refcount > 0)
		return;

	if (p->group != NULL)
		login_group_unref(p->group);

	o_stream_unref(&p->output);
	i_free(p);
}

static void login_process_init_env(struct login_group *group, pid_t pid)
{
	struct settings *set = group->set;

	child_process_init_env();

	/* setup access environment - needs to be done after
	   clean_child_process() since it clears environment. Don't set user
	   parameter since we don't want to call initgroups() for login
	   processes. */
	restrict_access_set_env(NULL, set->login_uid,
				set->server->login_gid, (gid_t)-1,
				set->login_chroot ? set->login_dir : NULL,
				0, 0, NULL);

	env_put("DOVECOT_MASTER=1");

	if (!set->ssl_disable) {
		const char *ssl_key_password;

		ssl_key_password = *set->ssl_key_password != '\0' ?
			set->ssl_key_password : ssl_manual_key_password;

		if (*set->ssl_ca_file != '\0') {
			env_put(t_strconcat("SSL_CA_FILE=",
					    set->ssl_ca_file, NULL));
		}
		env_put(t_strconcat("SSL_CERT_FILE=",
				    set->ssl_cert_file, NULL));
		env_put(t_strconcat("SSL_KEY_FILE=",
				    set->ssl_key_file, NULL));
		env_put(t_strconcat("SSL_KEY_PASSWORD=",
				    ssl_key_password, NULL));
		env_put("SSL_PARAM_FILE="SSL_PARAMETERS_FILENAME);
		if (*set->ssl_cipher_list != '\0') {
			env_put(t_strconcat("SSL_CIPHER_LIST=",
					    set->ssl_cipher_list, NULL));
		}
		env_put(t_strconcat("SSL_CERT_USERNAME_FIELD=",
				    set->ssl_cert_username_field, NULL));
		if (set->ssl_verify_client_cert)
			env_put("SSL_VERIFY_CLIENT_CERT=1");
	}

	if (set->disable_plaintext_auth)
		env_put("DISABLE_PLAINTEXT_AUTH=1");
	if (set->verbose_proctitle)
		env_put("VERBOSE_PROCTITLE=1");
	if (set->verbose_ssl)
		env_put("VERBOSE_SSL=1");
	if (set->server->auths->verbose)
		env_put("VERBOSE_AUTH=1");

	if (set->login_process_per_connection) {
		env_put("PROCESS_PER_CONNECTION=1");
		env_put("MAX_CONNECTIONS=1");
	} else {
		env_put(t_strdup_printf("MAX_CONNECTIONS=%u",
					set->login_max_connections));
	}

	env_put(t_strconcat("PROCESS_UID=", dec2str(pid), NULL));
	env_put(t_strconcat("GREETING=", set->login_greeting, NULL));
	env_put(t_strconcat("LOG_FORMAT_ELEMENTS=",
			    set->login_log_format_elements, NULL));
	env_put(t_strconcat("LOG_FORMAT=", set->login_log_format, NULL));
	env_put(t_strconcat("IMAP_ID_SEND=", set->imap_id_send, NULL));
	env_put(t_strconcat("IMAP_ID_LOG=", set->imap_id_log, NULL));

	if (group->mail_process_type == PROCESS_TYPE_IMAP) {
		env_put(t_strconcat("CAPABILITY_STRING=",
				    *set->imap_capability != '\0' ?
				    set->imap_capability :
				    set->imap_generated_capability, NULL));
	}
	if (*set->login_trusted_networks != '\0') {
		env_put(t_strconcat("TRUSTED_NETWORKS=",
				    set->login_trusted_networks, NULL));
	}
}

static pid_t create_login_process(struct login_group *group)
{
	struct log_io *log;
	const struct listener *listens;
	unsigned int max_log_lines_per_sec;
	const char *prefix;
	pid_t pid;
	ARRAY_TYPE(dup2) dups;
	unsigned int i, listen_count = 0, ssl_listen_count = 0;
	int fd[2], log_fd, cur_fd, tmp_fd;

	if (group->set->login_uid == 0)
		i_fatal("Login process must not run as root");

	/* create communication to process with a socket pair */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
		i_error("socketpair() failed: %m");
		return -1;
	}

	max_log_lines_per_sec =
		group->set->login_process_per_connection ? 10 : 0;
	log_fd = log_create_pipe(&log, /*max_log_lines_per_sec*/0);
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
		prefix = t_strdup_printf("%s-login: ",
				process_names[group->mail_process_type]);
		log_set_prefix(log, prefix);
		log_set_pid(log, pid);

		net_set_nonblock(fd[0], TRUE);
		fd_close_on_exec(fd[0], TRUE);
		(void)login_process_new(group, pid, fd[0], FALSE);
		(void)close(fd[1]);
		(void)close(log_fd);
		return pid;
	}

	prefix = t_strdup_printf("master-%s-login: ",
				 process_names[group->mail_process_type]);
	log_set_prefix(log, prefix);

	t_array_init(&dups, 16);
	dup2_append(&dups, null_fd, STDIN_FILENO);
	/* redirect writes to stdout also to error log. For example OpenSSL
	   can be made to log its debug messages to stdout. */
	dup2_append(&dups, log_fd, STDOUT_FILENO);
	dup2_append(&dups, log_fd, STDERR_FILENO);
	dup2_append(&dups, fd[1], LOGIN_MASTER_SOCKET_FD);

	/* redirect listener fds */
	cur_fd = LOGIN_MASTER_SOCKET_FD + 1;
	if (array_is_created(&group->set->listens)) {
		listens = array_get(&group->set->listens, &listen_count);
		for (i = 0; i < listen_count; i++, cur_fd++)
			dup2_append(&dups, listens[i].fd, cur_fd);
	}

	if (array_is_created(&group->set->ssl_listens)) {
		listens = array_get(&group->set->ssl_listens,
				    &ssl_listen_count);
		for (i = 0; i < ssl_listen_count; i++, cur_fd++)
			dup2_append(&dups, listens[i].fd, cur_fd);
	}

	if (dup2_array(&dups) < 0)
		i_fatal("Failed to dup2() fds");

	/* don't close any of these */
	for (tmp_fd = 0; tmp_fd <= cur_fd; tmp_fd++)
		fd_close_on_exec(tmp_fd, FALSE);

	(void)close(fd[0]);
	(void)close(fd[1]);

	login_process_init_env(group, getpid());

	env_put(t_strdup_printf("LISTEN_FDS=%u", listen_count));
	env_put(t_strdup_printf("SSL_LISTEN_FDS=%u", ssl_listen_count));

	if (!group->set->login_chroot) {
		/* no chrooting, but still change to the directory */
		if (chdir(group->set->login_dir) < 0) {
			i_fatal("chdir(%s) failed: %m",
				group->set->login_dir);
		}
	}

	restrict_process_size(group->set->login_process_size, (unsigned int)-1);

	/* make sure we don't leak syslog fd, but do it last so that
	   any errors above will be logged */
	closelog();

	client_process_exec(group->set->login_executable, "");
	i_fatal_status(FATAL_EXEC, "execv(%s) failed: %m",
		       group->set->login_executable);
	return -1;
}

static void
login_process_destroyed(struct child_process *process,
			pid_t pid ATTR_UNUSED, bool abnormal_exit)
{
	struct login_process *p = (struct login_process *)process;

	i_assert(!p->inetd_child);

	if (abnormal_exit) {
		/* don't start raising the process count if they're dying all
		   the time */
		if (p->group != NULL)
			p->group->wanted_processes_count = 0;
	}

	login_process_exited(p);
}

void login_processes_destroy_all(void)
{
	struct hash_iterate_context *iter;
	void *key, *value;

	iter = hash_iterate_init(processes);
	while (hash_iterate(iter, &key, &value)) {
		struct login_process *p = value;

		if (p->process.type == PROCESS_TYPE_LOGIN)
			login_process_destroy(p);
	}
	hash_iterate_deinit(&iter);

	while (login_groups != NULL) {
		struct login_group *group = login_groups;

		login_groups = group->next;
		login_group_unref(group);
	}
}

static void login_processes_notify_group(struct login_group *group)
{
	struct hash_iterate_context *iter;
	struct master_login_reply reply;
	void *key, *value;

	memset(&reply, 0, sizeof(reply));

	iter = hash_iterate_init(processes);
	while (hash_iterate(iter, &key, &value)) {
		struct login_process *p = value;

		if (p->process.type == PROCESS_TYPE_LOGIN && p->group == group)
			(void)o_stream_send(p->output, &reply, sizeof(reply));
	}
	hash_iterate_deinit(&iter);
}

static int login_group_start_missings(struct login_group *group)
{
	if (group->set->login_process_per_connection &&
	    group->processes >= group->set->login_max_processes_count &&
	    group->listening_processes == 0) {
		/* destroy the oldest listening process. non-listening
		   processes are logged in users who we don't want to kick out
		   because someone's started flooding */
		if (group->oldest_prelogin_process != NULL &&
		    group->oldest_prelogin_process->initialized)
			login_process_destroy(group->oldest_prelogin_process);
	}

	/* we want to respond fast when multiple clients are connecting
	   at once, but we also want to prevent fork-bombing. use the
	   same method as apache: check once a second if we need new
	   processes. if yes and we've used all the existing processes,
	   double their amount (unless we've hit the high limit).
	   Then for each second that didn't use all existing processes,
	   drop the max. process count by one. */
	if (group->wanted_processes_count < group->set->login_processes_count) {
		group->wanted_processes_count =
			group->set->login_processes_count;
	} else if (group->listening_processes == 0)
		group->wanted_processes_count *= 2;
	else if (group->wanted_processes_count >
		 group->set->login_processes_count)
		group->wanted_processes_count--;

	while (group->listening_processes < group->wanted_processes_count &&
	       group->processes < group->set->login_max_processes_count) {
		if (create_login_process(group) < 0)
			return -1;
	}

	if (group->listening_processes == 0 &&
	    !group->set->login_process_per_connection) {
		/* we've reached our limit. notify the processes to start
		   listening again which makes them kill some of their
		   oldest clients when accepting the next connection */
		login_processes_notify_group(group);
	}
	return 0;
}

static void login_processes_stall(void)
{
	if (logins_stalled || IS_INETD())
		return;

	i_error("Temporary failure in creating login processes, "
		"slowing down for now");
	logins_stalled = TRUE;

	timeout_remove(&to);
	to = timeout_add(60*1000, login_processes_start_missing, NULL);
}

static void
login_processes_start_missing(void *context ATTR_UNUSED)
{
	struct login_group *group;

	if (!have_initialized_auth_processes) {
		/* don't create login processes before at least one auth
		   process has finished initializing */
		return;
	}

	if (login_groups == NULL)
		login_process_groups_create();

	for (group = login_groups; group != NULL; group = group->next) {
		if (login_group_start_missings(group) < 0) {
			login_processes_stall();
			return;
		}
	}
}

static int login_process_send_env(struct login_process *p)
{
	extern char **environ;
	char **env;
	ssize_t len;
	int ret = 0;

	/* this will clear our environment. luckily we don't need it. */
	login_process_init_env(p->group, p->pid);

	for (env = environ; *env != NULL; env++) {
		len = strlen(*env);

		if (o_stream_send(p->output, *env, len) != len ||
		    o_stream_send(p->output, "\n", 1) != 1) {
			ret = -1;
			break;
		}
	}

	if (!p->group->set->login_chroot) {
		/* if we're not chrooting, we need to tell login process
		   where its base directory is */
		const char *str = t_strdup_printf("LOGIN_DIR=%s\n",
						  p->group->set->login_dir);
		len = strlen(str);
		if (o_stream_send(p->output, str, len) != len)
			ret = -1;
	}

	if (ret == 0 && o_stream_send(p->output, "\n", 1) != 1)
		ret = -1;

	env_clean();
	return ret;
}

static bool login_process_init_group(struct login_process *p)
{
	p->group->refcount++;
	p->group->processes++;
	p->group->listening_processes++;

	if (login_process_send_env(p) < 0) {
		i_error("login: Couldn't send environment");
		return FALSE;
	}

	return TRUE;
}

static void inetd_login_accept(void *context ATTR_UNUSED)
{
        struct login_process *p;
	int fd;

	fd = net_accept(inetd_login_fd, NULL, NULL);
	if (fd < 0) {
		if (fd < -1)
			i_error("accept(inetd_login_fd) failed: %m");
	} else {
		net_set_nonblock(fd, TRUE);
		fd_close_on_exec(fd, TRUE);

		p = login_process_new(NULL, ++login_pid_counter, fd, TRUE);
		p->initialized = TRUE;
	}
}

void login_processes_init(void)
{
	auth_id_counter = 0;
        login_pid_counter = 0;
	login_groups = NULL;

	child_process_set_destroy_callback(PROCESS_TYPE_LOGIN,
					   login_process_destroyed);

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
		timeout_remove(&to);
	if (io_listen != NULL)
		io_remove(&io_listen);
}
