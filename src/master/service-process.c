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
#include "llist.h"
#include "hostpid.h"
#include "env-util.h"
#include "fd-close-on-exec.h"
#include "restrict-access.h"
#include "restrict-process-size.h"
#include "eacces-error.h"
#include "master-service.h"
#include "master-service-settings.h"
#include "dup2-array.h"
#include "service.h"
#include "service-anvil.h"
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

/* Timeout chdir() completely after this many seconds */
#define CHDIR_TIMEOUT 30
/* Give a warning about chdir() taking a while if it took longer than this
   many seconds to finish. */
#define CHDIR_WARN_SECS 10

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

static void
validate_uid_gid(struct master_settings *set,
		 uid_t uid, gid_t gid, const char *user,
		 const struct service_process_auth_request *request)
{
	struct service_process *request_process =
		request == NULL ? NULL : &request->process->process;

	if (uid == 0) {
		i_fatal("User %s not allowed to log in using UNIX UID 0 "
			"(root logins are never allowed)", user);
	}

	if (request != NULL && request_process->service->uid == uid &&
	    master_uid != uid) {
		struct passwd *pw;

		pw = getpwuid(uid);
		i_fatal("User %s not allowed to log in using %s's "
			"UNIX UID %s%s (see http://wiki.dovecot.org/UserIds)",
			user, request_process->service->set->name,
			dec2str(uid), pw == NULL ? "" :
			t_strdup_printf("(%s)", pw->pw_name));
	}

	if (uid < (uid_t)set->first_valid_uid ||
	    (set->last_valid_uid != 0 && uid > (uid_t)set->last_valid_uid)) {
		struct passwd *pw;
		bool low = uid < (uid_t)set->first_valid_uid;

		pw = getpwuid(uid);
		i_fatal("User %s not allowed to log in using too %s "
			"UNIX UID %s%s (see %s in config file)",
			user, low ? "low" : "high",
			dec2str(uid), pw == NULL ? "" :
			t_strdup_printf("(%s)", pw->pw_name),
			low ? "first_valid_uid" : "last_valid_uid");
	}

	if (gid < (gid_t)set->first_valid_gid ||
	    (set->last_valid_gid != 0 && gid > (gid_t)set->last_valid_gid)) {
		struct group *gr;
		bool low = gid < (gid_t)set->first_valid_gid;

		gr = getgrgid(gid);
		i_fatal("User %s not allowed to log in using too %s primary "
			"UNIX group ID %s%s (see %s in config file)",
			user, low ? "low" : "high",
			dec2str(gid), gr == NULL ? "" :
			t_strdup_printf("(%s)", gr->gr_name),
			low ? "first_valid_gid" : "last_valid_gid");
	}
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

static void chdir_to_home(const struct restrict_access_settings *rset,
			  const char *user, const char *home)
{
	unsigned int left;
	int ret, chdir_errno;

	if (*home != '/') {
		i_fatal("user %s: Relative home directory paths not supported: "
			"%s", user, home);
	}

	/* if home directory is NFS-mounted, we might not have access to it as
	   root. Change the effective UID and GID temporarily to make it
	   work. */
	if (rset->uid != master_uid) {
		if (setegid(rset->gid) < 0)
			i_fatal("setegid(%s) failed: %m", dec2str(rset->gid));
		if (seteuid(rset->uid) < 0)
			i_fatal("seteuid(%s) failed: %m", dec2str(rset->uid));
	}

	alarm(CHDIR_TIMEOUT);
	ret = chdir(home);
	chdir_errno = errno;
	if ((left = alarm(0)) < CHDIR_TIMEOUT - CHDIR_WARN_SECS) {
		i_warning("user %s: chdir(%s) blocked for %u secs",
			  user, home, CHDIR_TIMEOUT - left);
	}

	errno = chdir_errno;
	if (ret == 0) {
		/* chdir succeeded */
	} else if ((errno == ENOENT || errno == ENOTDIR || errno == EINTR) &&
		   rset->chroot_dir == NULL) {
		/* Not chrooted, fallback to using /tmp.

		   ENOENT: No home directory yet, but it might be automatically
		     created by the service process, so don't complain.
		   ENOTDIR: This check is mainly for /dev/null home directory.
		   EINTR: chdir() timed out. */
	} else if (errno == EACCES) {
		i_fatal("user %s: %s", user, eacces_error_get("chdir", home));
	} else {
		i_fatal("user %s: chdir(%s) failed with uid %s: %m",
			user, home, dec2str(rset->uid));
	}
	/* Change UID back. No need to change GID back, it doesn't
	   really matter. */
	if (rset->uid != master_uid && seteuid(master_uid) < 0)
		i_fatal("seteuid(%s) failed: %m", dec2str(master_uid));

	if (ret < 0) {
		/* We still have to change to some directory where we have
		   rx-access. /tmp should exist everywhere. */
		if (chdir("/tmp") < 0)
			i_fatal("chdir(/tmp) failed: %m");
	}
}

static void
drop_privileges(struct service *service, const char *const *auth_args,
		const struct service_process_auth_request *request)
{
	struct master_settings *master_set = service->set->master_set;
	struct restrict_access_settings rset;
	const char *user, *home = NULL;
	bool disallow_root;

	if (auth_args != NULL && service->set->master_set->mail_debug)
		env_put("DEBUG=1");

	if (service->vsz_limit != 0)
		restrict_process_size(service->vsz_limit, -1U);

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

		validate_uid_gid(master_set, rset.uid, rset.gid, user,
				 request);
	}

	if (home != NULL)
		chdir_to_home(&rset, user, home);

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
	const struct master_service_settings *set = service->list->service_set;
	const char *const *p;

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
		env_put("DOVECONF_ENV=1");
		env_put(t_strconcat("LOG_PATH=", set->log_path, NULL));
		env_put(t_strconcat("INFO_LOG_PATH=", set->info_log_path, NULL));
		env_put(t_strconcat("DEBUG_LOG_PATH=", set->debug_log_path, NULL));
		env_put(t_strconcat("LOG_TIMESTAMP=", set->log_timestamp, NULL));
		env_put(t_strconcat("SYSLOG_FACILITY=", set->syslog_facility, NULL));
		break;
	default:
		env_put(t_strconcat(MASTER_CONFIG_FILE_ENV"=",
			services_get_config_socket_path(service->list), NULL));
		break;
	}

	env_put(t_strdup_printf(MASTER_CLIENT_LIMIT_ENV"=%u",
				service->client_limit));
	if (service->set->service_count != 0) {
		env_put(t_strdup_printf(MASTER_SERVICE_COUNT_ENV"=%u",
					service->set->service_count));
	}
	env_put(t_strdup_printf(MASTER_UID_ENV"=%u", uid));

	if (!service->set->master_set->version_ignore)
		env_put(MASTER_DOVECOT_VERSION_ENV"="PACKAGE_VERSION);

	if (*ssl_manual_key_password != '\0' && service->have_inet_listeners) {
		/* manually given SSL password. give it only to services
		   that have inet listeners. */
		env_put(t_strconcat(MASTER_SSL_KEY_PASSWORD_ENV"=",
				    ssl_manual_key_password, NULL));
	}
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

static const char **
get_extra_args(struct service *service,
	       const struct service_process_auth_request *request,
	       const char *const *auth_args)
{
	const char **extra;

	if (!service->set->master_set->verbose_proctitle || request == NULL)
		return NULL;

	extra = t_new(const char *, 2);
	extra[0] = t_strdup_printf("[%s %s]", auth_args[0],
				   net_ip2addr(&request->remote_ip));
	return extra;
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

	if (service->to_throttle != NULL) {
		/* throttling service, don't create new processes */
		return NULL;
	}
	if (service->process_count >= service->process_limit) {
		/* we should get here only with auth dest services */
		i_warning("service(%s): process_limit reached, "
			  "dropping this client connection",
			  service->set->name);
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
		drop_privileges(service, auth_args, request);
		process_exec(service->executable,
			     get_extra_args(service, request, auth_args));
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
	case SERVICE_TYPE_ANVIL:
		service_anvil_process_created(service);
		/* fall through */
	default:
		process = i_new(struct service_process, 1);
		process->service = service;
		i_assert(fd[0] == -1);
		break;
	}

	DLLIST_PREPEND(&service->processes, process);
	process->refcount = 1;
	process->pid = pid;
	process->uid = uid;
	process->to_status =
		timeout_add(SERVICE_FIRST_STATUS_TIMEOUT_SECS * 1000,
			    service_process_status_timeout, process);

	process->available_count = service->client_limit;
	service->process_count++;
	service->process_avail++;

	service_list_ref(service->list);
	hash_table_insert(service_pids, &process->pid, process);
	return process;
}

void service_process_destroy(struct service_process *process)
{
	struct service *service = process->service;
	struct service_list *service_list = service->list;

	DLLIST_REMOVE(&service->processes, process);
	hash_table_remove(service_pids, &process->pid);

	if (process->available_count > 0)
		service->process_avail--;
	service->process_count--;
	i_assert(service->process_avail <= service->process_count);

	if (process->to_status != NULL)
		timeout_remove(&process->to_status);
	if (process->to_idle != NULL)
		timeout_remove(&process->to_idle);

	switch (process->service->type) {
	case SERVICE_TYPE_AUTH_SERVER:
		service_process_auth_server_deinit(process);
		break;
	case SERVICE_TYPE_AUTH_SOURCE:
		service_process_auth_source_deinit(process);
		break;
	case SERVICE_TYPE_ANVIL:
		service_anvil_process_destroyed(service);
		break;
	default:
		break;
	}

	if (service->list->log_byes != NULL)
		service_process_notify_add(service->list->log_byes, process);

	process->destroyed = TRUE;
	service_process_unref(process);

	if (service->process_count < service->process_limit &&
	    service->type == SERVICE_TYPE_AUTH_SOURCE)
		service_processes_auth_source_notify(service, FALSE);

	service_list_unref(service_list);
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
		if (service->vsz_limit == 0)
			return "Out of memory";
		return t_strdup_printf("Out of memory (vsz_limit=%u MB, "
				       "you may need to increase it)",
				       service->vsz_limit);
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
