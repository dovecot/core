/* Copyright (c) 2005-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "array.h"
#include "aqueue.h"
#include "ioloop.h"
#include "istream.h"
#include "ostream.h"
#include "write-full.h"
#include "base64.h"
#include "hash.h"
#include "str.h"
#include "hostpid.h"
#include "env-util.h"
#include "fd-close-on-exec.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "dup2-array.h"
#include "service.h"
#include "service-log.h"
#include "service-auth-server.h"
#include "service-auth-source.h"
#include "service-process-notify.h"
#include "service-process.h"

#include <grp.h>
#include <pwd.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <signal.h>
#include <sys/wait.h>

static void
service_dup_fds(struct service *service, int auth_fd, int std_fd,
		bool give_anvil_fd)
{
	struct service_listener *const *listeners;
	ARRAY_TYPE(dup2) dups;
	unsigned int i, count, n = 0, socket_listener_count, ssl_socket_count;

	/* stdin/stdout is already redirected to /dev/null. Other master fds
	   should have been opened with fd_close_on_exec() so we don't have to
	   worry about them.

	   because the destination fd might be another one's source fd we have
	   to be careful not to overwrite anything. dup() the fd when needed */

        socket_listener_count = 0;
	listeners = array_get(&service->listeners, &count);
	t_array_init(&dups, count + 10);

	switch (service->type) {
	case SERVICE_TYPE_LOG:
		i_assert(n == 0);
		services_log_dup2(&dups, service->list, MASTER_LISTEN_FD_FIRST,
				  &socket_listener_count);
		n += socket_listener_count;
		break;
	case SERVICE_TYPE_ANVIL:
		/* nonblocking anvil fd must be the first one. anvil treats it
		   as the master's fd */
		dup2_append(&dups, service->list->nonblocking_anvil_fd[0],
			    MASTER_LISTEN_FD_FIRST + n++);
		dup2_append(&dups, service->list->blocking_anvil_fd[0],
			    MASTER_LISTEN_FD_FIRST + n++);
		socket_listener_count += 2;
		break;
	default:
		break;
	}

	/* first add non-ssl listeners */
	for (i = 0; i < count; i++) {
		if (listeners[i]->fd != -1 &&
		    (listeners[i]->type != SERVICE_LISTENER_INET ||
		     !listeners[i]->set.inetset.set->ssl)) {
			dup2_append(&dups, listeners[i]->fd,
				    MASTER_LISTEN_FD_FIRST + n);
			n++; socket_listener_count++;
		}
	}
	/* then ssl-listeners */
	ssl_socket_count = 0;
	for (i = 0; i < count; i++) {
		if (listeners[i]->fd != -1 &&
		    listeners[i]->type == SERVICE_LISTENER_INET &&
		    listeners[i]->set.inetset.set->ssl) {
			dup2_append(&dups, listeners[i]->fd,
				    MASTER_LISTEN_FD_FIRST + n);
			n++; socket_listener_count++;
			ssl_socket_count++;
		}
	}

	if (!give_anvil_fd)
		dup2_append(&dups, null_fd, MASTER_ANVIL_FD);
	else {
		dup2_append(&dups, service->list->blocking_anvil_fd[1],
			    MASTER_ANVIL_FD);
	}
	dup2_append(&dups, service->status_fd[1], MASTER_STATUS_FD);

	switch (service->type) {
	case SERVICE_TYPE_AUTH_SOURCE:
	case SERVICE_TYPE_AUTH_SERVER:
		i_assert(auth_fd != -1);
		dup2_append(&dups, auth_fd, MASTER_AUTH_FD);
		env_put(t_strdup_printf("MASTER_AUTH_FD=%d", MASTER_AUTH_FD));
		break;
	default:
		i_assert(auth_fd == -1);
		dup2_append(&dups, null_fd, MASTER_AUTH_FD);
		break;
	}

	if (std_fd != -1) {
		dup2_append(&dups, std_fd, STDIN_FILENO);
		dup2_append(&dups, std_fd, STDOUT_FILENO);
		env_put("LOGGED_IN=1");
	}

	if (service->type != SERVICE_TYPE_LOG) {
		/* set log file to stderr. dup2() here immediately so that
		   we can set up logging to it without causing any log messages
		   to be lost. */
		i_assert(service->log_fd[1] != -1);

		env_put("LOG_SERVICE=1");
		if (dup2(service->log_fd[1], STDERR_FILENO) < 0)
			i_fatal("dup2(log fd) failed: %m");
		i_set_failure_internal();
	} else {
		dup2_append(&dups, null_fd, STDERR_FILENO);
	}

	/* make sure we don't leak syslog fd. try to do it as late as possible,
	   but also before dup2()s in case syslog fd is one of them. */
	closelog();

	if (dup2_array(&dups) < 0)
		service_error(service, "dup2s failed");

	env_put(t_strdup_printf("SOCKET_COUNT=%d", socket_listener_count));
	env_put(t_strdup_printf("SSL_SOCKET_COUNT=%d", ssl_socket_count));
}

static int validate_uid_gid(struct master_settings *set, uid_t uid, gid_t gid,
			    const char *user)
{
	if (uid == 0) {
		i_error("User %s not allowed to log in using UNIX UID 0 "
			"(root logins are never allowed)", user);
		return FALSE;
	}

	if (uid < (uid_t)set->first_valid_uid ||
	    (set->last_valid_uid != 0 && uid > (uid_t)set->last_valid_uid)) {
		struct passwd *pw;

		pw = getpwuid(uid);
		i_error("User %s not allowed to log in using too %s "
			"UNIX UID %s%s (see first_valid_uid in config file)",
			user,
			uid < (uid_t)set->first_valid_uid ? "low" : "high",
			dec2str(uid), pw == NULL ? "" :
			t_strdup_printf("(%s)", pw->pw_name));
		return FALSE;
	}

	if (gid < (gid_t)set->first_valid_gid ||
	    (set->last_valid_gid != 0 && gid > (gid_t)set->last_valid_gid)) {
		struct group *gr;

		gr = getgrgid(gid);
		i_error("User %s not allowed to log in using too %s "
			"UNIX GID %s%s (see first_valid_gid in config file)",
			user,
			gid < (gid_t)set->first_valid_gid ? "low" : "high",
			dec2str(gid), gr == NULL ? "" :
			t_strdup_printf("(%s)", gr->gr_name));
		return FALSE;
	}

	return TRUE;
}

static void auth_args_apply(const char *const *args,
			    struct restrict_access_settings *rset,
			    const char **home)
{
	const char *key, *value;
	string_t *expanded_vars;

	expanded_vars = t_str_new(128);
	str_append(expanded_vars, "VARS_EXPANDED=");
	for (; *args != NULL; args++) {
		if (strncmp(*args, "uid=", 4) == 0)
			rset->uid = (uid_t)strtoul(*args + 4, NULL, 10);
		else if (strncmp(*args, "gid=", 4) == 0)
			rset->gid = (gid_t)strtoul(*args + 4, NULL, 10);
		else if (strncmp(*args, "home=", 5) == 0) {
			*home = *args + 5;
			env_put(t_strconcat("HOME=", *args + 5, NULL));
		} else if (strncmp(*args, "chroot=", 7) == 0)
			rset->chroot_dir = *args + 7;
		else if (strncmp(*args, "system_groups_user=", 19) == 0)
			rset->system_groups_user = *args + 19;
		else if (strncmp(*args, "mail_access_groups=", 19) == 0) {
			rset->extra_groups =
				rset->extra_groups == NULL ? *args + 19 :
				t_strconcat(*args + 19, ",",
					    rset->extra_groups, NULL);
		} else {
			/* unknown, set as environment */
			value = strchr(*args, '=');
			if (value == NULL) {
				/* boolean */
				key = *args;
				value = "=1";
			} else {
				key = t_strdup_until(*args, value);
				if (strcmp(key, "mail") == 0) {
					/* FIXME: kind of ugly to have it
					   here.. */
					key = "mail_location";
				}
			}
			str_append(expanded_vars, key);
			str_append_c(expanded_vars, ' ');
			env_put(t_strconcat(t_str_ucase(key), value, NULL));
		}
	}
	env_put(str_c(expanded_vars));
}        

static void auth_success_write(void)
{
	int fd;

	if (auth_success_written)
		return;

	fd = creat(AUTH_SUCCESS_PATH, 0666);
	if (fd == -1)
		i_error("creat(%s) failed: %m", AUTH_SUCCESS_PATH);
	else
		(void)close(fd);
	auth_success_written = TRUE;
}

static void drop_privileges(struct service *service,
			    const char *const *auth_args)
{
	struct master_settings *master_set = service->set->master_set;
	struct restrict_access_settings rset;
	const char *user, *home = NULL;
	bool disallow_root;

	if (auth_args != NULL && service->set->master_set->mail_debug)
		env_put("DEBUG=1");

	if (service->set->vsz_limit != 0)
		restrict_process_size(service->set->vsz_limit, -1U);

	restrict_access_init(&rset);
	rset.uid = service->uid;
	rset.gid = service->gid;
	rset.privileged_gid = service->privileged_gid;
	rset.chroot_dir = *service->set->chroot == '\0' ? NULL :
		service->set->chroot;
	rset.extra_groups = service->extra_gids;

	if (auth_args == NULL) {
		/* non-authenticating service. don't use *_valid_gid checks */
	} else {
		i_assert(auth_args[0] != NULL);

		rset.first_valid_gid = master_set->first_valid_gid;
		rset.last_valid_gid = master_set->last_valid_gid;

		user = auth_args[0];
		env_put(t_strconcat("USER=", user, NULL));

		auth_success_write();
		auth_args_apply(auth_args + 1, &rset, &home);

		if (!validate_uid_gid(master_set, rset.uid, rset.gid, user))
			exit(FATAL_DEFAULT);
	}

	if (home != NULL) {
		if (chdir(home) < 0 && errno != ENOENT)
			i_error("chdir(%s) failed: %m", home);
	}

	if (service->set->drop_priv_before_exec) {
		disallow_root = service->type == SERVICE_TYPE_AUTH_SERVER ||
			service->type == SERVICE_TYPE_AUTH_SOURCE;
		restrict_access(&rset, home, disallow_root);
	} else {
		restrict_access_set_env(&rset);
	}
}

static void
service_process_setup_environment(struct service *service, unsigned int uid)
{
	const struct master_service_settings *set;
        struct service_listener *const *listeners;
	const char *const *p;
	unsigned int limit, count;

	/* remove all environment, and put back what we need */
	env_clean();
	for (p = service->list->child_process_env; *p != NULL; p++)
		env_put(*p);

	switch (service->type) {
	case SERVICE_TYPE_CONFIG:
		env_put(t_strconcat(MASTER_CONFIG_FILE_ENV"=",
				    service->config_file_path, NULL));
		break;
	case SERVICE_TYPE_LOG:
		/* give the log's configuration directly, so it won't depend
		   on config process */
		set = master_service_settings_get(master_service);
		env_put("DOVECONF_ENV=1");
		env_put(t_strconcat("LOG_PATH=", set->log_path, NULL));
		env_put(t_strconcat("INFO_LOG_PATH=", set->info_log_path, NULL));
		env_put(t_strconcat("LOG_TIMESTAMP=", set->log_timestamp, NULL));
		env_put(t_strconcat("SYSLOG_FACILITY=", set->syslog_facility, NULL));
		break;
	default:
		listeners = array_get(&service->list->config->listeners,
				      &count);
		i_assert(count > 0);
		env_put(t_strconcat(MASTER_CONFIG_FILE_ENV"=",
				    listeners[0]->set.fileset.set->path, NULL));
		break;
	}

	limit = service->set->client_limit;
	if (limit == 0) {
		/* fallback to default limit */
		limit = service->set->master_set->default_client_limit;
	}

	env_put(t_strdup_printf(MASTER_CLIENT_LIMIT_ENV"=%u", limit));
	env_put(t_strdup_printf(MASTER_UID_ENV"=%u", uid));

	if (!service->set->master_set->version_ignore)
		env_put(MASTER_DOVECOT_VERSION_ENV"="PACKAGE_VERSION);
}

static void service_process_status_timeout(struct service_process *process)
{
	service_error(process->service,
		      "Initial status notification not received in %d "
		      "seconds, killing the process",
		      SERVICE_FIRST_STATUS_TIMEOUT_SECS);
	if (kill(process->pid, SIGKILL) < 0 && errno != ESRCH) {
		service_error(process->service, "kill(%s, SIGKILL) failed: %m",
			      dec2str(process->pid));
	}
	timeout_remove(&process->to_status);
}

static void
handle_request(const struct service_process_auth_request *request)
{
	string_t *str;

	if (request == NULL)
		return;

	if (request->data_size > 0) {
		str = t_str_new(request->data_size*3);
		str_append(str, "CLIENT_INPUT=");
		base64_encode(request->data, request->data_size, str);
		env_put(str_c(str));
	}

	env_put(t_strconcat("LOCAL_IP=", net_ip2addr(&request->local_ip), NULL));
	env_put(t_strconcat("IP=", net_ip2addr(&request->remote_ip), NULL));
}

struct service_process *
service_process_create(struct service *service, const char *const *auth_args,
		       const struct service_process_auth_request *request)
{
	static unsigned int uid_counter = 0;
	struct service_process *process;
	unsigned int uid = ++uid_counter;
	int fd[2];
	pid_t pid;

	if (!service->listening) {
		/* probably throttling service, don't create new processes */
		return NULL;
	}

	switch (service->type) {
	case SERVICE_TYPE_AUTH_SOURCE:
	case SERVICE_TYPE_AUTH_SERVER:
		if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) < 0) {
			service_error(service, "socketpair() failed: %m");
			return NULL;
		}
		fd_close_on_exec(fd[0], TRUE);
		fd_close_on_exec(fd[1], TRUE);
		break;
	default:
		fd[0] = fd[1] = -1;
		break;
	}

	pid = fork();
	if (pid < 0) {
		service_error(service, "fork() failed: %m");
		if (fd[0] != -1) {
			(void)close(fd[0]);
			(void)close(fd[1]);
		}
		return NULL;
	}
	if (pid == 0) {
		/* child */
		if (fd[0] != -1)
			(void)close(fd[0]);
		service_process_setup_environment(service, uid);
		handle_request(request);
		service_dup_fds(service, fd[1], request == NULL ? -1 :
				request->fd, auth_args != NULL);
		drop_privileges(service, auth_args);
		process_exec(service->executable, NULL);
	}

	switch (service->type) {
	case SERVICE_TYPE_AUTH_SERVER:
		process = i_malloc(sizeof(struct service_process_auth_server));
		process->service = service;
		service_process_auth_server_init(process, fd[0]);
		(void)close(fd[1]);
		break;
	case SERVICE_TYPE_AUTH_SOURCE:
		process = i_malloc(sizeof(struct service_process_auth_source));
		process->service = service;
		service_process_auth_source_init(process, fd[0]);
		(void)close(fd[1]);
		break;
	default:
		process = i_new(struct service_process, 1);
		process->service = service;
		i_assert(fd[0] == -1);
		break;
	}
		
	process->refcount = 1;
	process->pid = pid;
	process->uid = uid;
	process->to_status =
		timeout_add(SERVICE_FIRST_STATUS_TIMEOUT_SECS * 1000,
			    service_process_status_timeout, process);

	process->available_count = service->set->client_limit;
	if (process->available_count == 0) {
		/* fallback to default limit */
		process->available_count =
			service->set->master_set->default_client_limit;
	}

	service->process_count++;
	service->process_avail++;

	hash_table_insert(service->list->pids, &process->pid, process);
	return process;
}

void service_process_destroy(struct service_process *process)
{
	struct service *service = process->service;

	hash_table_remove(service->list->pids, &process->pid);

	if (process->available_count > 0)
		service->process_avail--;
	service->process_count--;
	i_assert(service->process_avail <= service->process_count);

	if (process->to_status != NULL)
		timeout_remove(&process->to_status);

	switch (process->service->type) {
	case SERVICE_TYPE_AUTH_SERVER:
		service_process_auth_server_deinit(process);
		break;
	case SERVICE_TYPE_AUTH_SOURCE:
		service_process_auth_source_deinit(process);
		break;
	default:
		break;
	}

	if (service->list->log_byes != NULL)
		service_process_notify_add(service->list->log_byes, process);

	process->destroyed = TRUE;
	service_process_unref(process);
}

void service_process_ref(struct service_process *process)
{
	i_assert(process->refcount > 0);

	process->refcount++;
}

int service_process_unref(struct service_process *process)
{
	i_assert(process->refcount > 0);

	if (--process->refcount > 0)
		return TRUE;

	i_assert(process->destroyed);

	i_free(process);
	return FALSE;
}

static const char *
get_exit_status_message(struct service *service, enum fatal_exit_status status)
{
	switch (status) {
	case FATAL_LOGOPEN:
		return "Can't open log file";
	case FATAL_LOGWRITE:
		return "Can't write to log file";
	case FATAL_LOGERROR:
		return "Internal logging error";
	case FATAL_OUTOFMEM:
		if (service->set->vsz_limit == 0)
			return "Out of memory";
		return t_strdup_printf("Out of memory (vsz_limit=%u MB, "
				       "you may need to increase it)",
				       service->set->vsz_limit);
	case FATAL_EXEC:
		return "exec() failed";

	case FATAL_DEFAULT:
		return "Fatal failure";
	}

	return NULL;
}

static void log_coredump(struct service *service ATTR_UNUSED,
			 string_t *str, int status)
{
#ifdef WCOREDUMP
	int signum = WTERMSIG(status);

	if (WCOREDUMP(status)) {
		str_append(str, " (core dumped)");
		return;
	}

	if (signum != SIGABRT && signum != SIGSEGV && signum != SIGBUS)
		return;

	/* let's try to figure out why we didn't get a core dump */
	if (core_dumps_disabled) {
		str_printfa(str, " (core dumps disabled)");
		return;
	}

#ifdef HAVE_PR_SET_DUMPABLE
	if (!service->set->drop_priv_before_exec) {
		str_append(str, " (core not dumped - set drop_priv_before_exec=yes)");
		return;
	}
	if (*service->set->privileged_group != '\0') {
		str_append(str, " (core not dumped - privileged_group prevented it)");
		return;
	}
#endif

	str_append(str, " (core not dumped)");
#endif
}

static void
service_process_get_status_error(string_t *str, struct service_process *process,
				 int status, bool *default_fatal_r)
{
	struct service *service = process->service;
	const char *msg;

	*default_fatal_r = FALSE;

	str_printfa(str, "service(%s): child %s ", service->set->name,
		    dec2str(process->pid));
	if (WIFSIGNALED(status)) {
		str_printfa(str, "killed with signal %d", WTERMSIG(status));
		log_coredump(service, str, status);
		return;
	}
	if (!WIFEXITED(status)) {
		str_printfa(str, "died with status %d", status);
		return;
	}

	status = WEXITSTATUS(status);
	if (status == 0) {
		str_truncate(str, 0);
		return;
	}
	str_printfa(str, "returned error %d", status);

	msg = get_exit_status_message(service, status);
	if (msg != NULL)
		str_printfa(str, " (%s)", msg);

	if (status == FATAL_DEFAULT)
		*default_fatal_r = TRUE;
}

static void service_process_log(struct service_process *process,
				bool default_fatal, const char *str)
{
	const char *data;

	if (!default_fatal || process->service->log_fd[1] == -1) {
		i_error("%s", str);
		return;
	}

	/* log it via the log process in charge of handling
	   this process's logging */
	data = t_strdup_printf("%d %s DEFAULT-FATAL %s\n",
			       process->service->log_process_internal_fd,
			       dec2str(process->pid), str);
	if (write(process->service->list->master_log_fd[1],
		  data, strlen(data)) < 0) {
		i_error("write(log process) failed: %m");
		i_error("%s", str);
	}
}

void service_process_log_status_error(struct service_process *process,
				      int status)
{
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		/* fast path */
		return;
	}
	T_BEGIN {
		string_t *str = t_str_new(256);
		bool default_fatal;

		service_process_get_status_error(str, process, status,
						 &default_fatal);
		if (str_len(str) > 0)
			service_process_log(process, default_fatal, str_c(str));
	} T_END;
}
