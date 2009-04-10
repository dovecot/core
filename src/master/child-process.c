/* Copyright (c) 2002-2009 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "lib-signals.h"
#include "array.h"
#include "hash.h"
#include "str.h"
#include "env-util.h"
#include "child-process.h"

#include <unistd.h>
#include <syslog.h>
#include <sys/wait.h>

const char *process_names[PROCESS_TYPE_MAX] = {
	"unknown",
	"auth",
	"auth-worker",
	"login",
	"imap",
	"pop3",
	"ssl-build-param",
	"dict"
};

struct hash_table *processes;
static child_process_destroy_callback_t *destroy_callbacks[PROCESS_TYPE_MAX];

struct child_process *child_process_lookup(pid_t pid)
{
	return hash_table_lookup(processes, POINTER_CAST(pid));
}

void child_process_add(pid_t pid, struct child_process *process)
{
	hash_table_insert(processes, POINTER_CAST(pid), process);
}

void child_process_remove(pid_t pid)
{
	hash_table_remove(processes, POINTER_CAST(pid));
}

void child_process_init_env(const struct master_settings *set)
{
	/* remove all environment, we don't need them */
	env_clean();

	/* we'll log through master process */
	env_put("LOG_TO_MASTER=1");
	if (env_tz != NULL)
		env_put(t_strconcat("TZ=", env_tz, NULL));

	if (master_set != NULL && !set->version_ignore)
		env_put("DOVECOT_VERSION="PACKAGE_VERSION);
#ifdef DEBUG
	if (gdb) env_put("GDB=1");
#endif
}

void client_process_exec(const char *cmd, const char *title)
{
	const char **argv;

	/* very simple argument splitting. */
	if (*title == '\0')
		argv = t_strsplit(cmd, " ");
	else
		argv = t_strsplit(t_strconcat(cmd, " ", title, NULL), " ");

	client_process_exec_argv(argv[0], argv);
}

void client_process_exec_argv(const char *executable, const char **argv)
{
	const char *p;

	/* hide the path, it's ugly */
	p = strrchr(argv[0], '/');
	if (p != NULL) argv[0] = p+1;

	execv(executable, (char **)argv);
}

static const char *get_exit_status_message(enum fatal_exit_status status,
					   enum process_type process_type)
{
	switch (status) {
	case FATAL_LOGOPEN:
		return "Can't open log file";
	case FATAL_LOGWRITE:
		return "Can't write to log file";
	case FATAL_LOGERROR:
		return "Internal logging error";
	case FATAL_OUTOFMEM:
		switch (process_type) {
		case PROCESS_TYPE_AUTH:
		case PROCESS_TYPE_AUTH_WORKER:
			return "Out of memory - see auth_process_size setting";
		case PROCESS_TYPE_LOGIN:
			return "Out of memory - see login_process_size setting";
		case PROCESS_TYPE_IMAP:
		case PROCESS_TYPE_POP3:
			return "Out of memory - see mail_process_size setting";
		case PROCESS_TYPE_UNKNOWN:
		case PROCESS_TYPE_SSL_PARAM:
		case PROCESS_TYPE_DICT:
		case PROCESS_TYPE_MAX:
			break;
		}
		return "Out of memory";
	case FATAL_EXEC:
		return "exec() failed";

	case FATAL_DEFAULT:
		return "Fatal failure";
	}

	return NULL;
}

static void
log_coredump(string_t *str, enum process_type process_type, int status)
{
#ifdef WCOREDUMP
	struct master_auth_settings *const *auth_set;
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

	switch (process_type) {
	case PROCESS_TYPE_LOGIN:
#ifdef HAVE_PR_SET_DUMPABLE
		str_append(str, " (core not dumped - add -D to login_executable)");
		return;
#else
		break;
#endif
	case PROCESS_TYPE_IMAP:
	case PROCESS_TYPE_POP3:
#ifndef HAVE_PR_SET_DUMPABLE
		if (!master_set->defaults->mail_drop_priv_before_exec) {
			str_append(str, " (core not dumped - set mail_drop_priv_before_exec=yes)");
			return;
		}
		if (*master_set->defaults->mail_privileged_group != '\0') {
			str_append(str, " (core not dumped - mail_privileged_group prevented it)");
			return;
		}
#endif
		str_append(str, " (core not dumped - is home dir set?)");
		return;
	case PROCESS_TYPE_AUTH:
	case PROCESS_TYPE_AUTH_WORKER:
		auth_set = array_idx(&master_set->defaults->auths, 0);
		if (auth_set[0]->uid == 0)
			break;
#ifdef HAVE_PR_SET_DUMPABLE
		str_printfa(str, " (core not dumped - "
			    "no permissions for auth user %s in %s?)",
			    auth_set[0]->user, master_set->defaults->base_dir);
#else
		str_append(str, " (core not dumped - auth user is not root)");
#endif
		return;
	default:
		break;
	}
	str_append(str, " (core not dumped)");
#endif
}

static void sigchld_handler(const siginfo_t *si ATTR_UNUSED,
			    void *context ATTR_UNUSED)
{
	struct child_process *process;
	const char *process_type_name, *msg;
	enum process_type process_type;
	string_t *str;
	pid_t pid;
	int status;
	bool abnormal_exit;

	str = t_str_new(128);
	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		/* get the type and remove from hash */
		str_truncate(str, 0);
		process = child_process_lookup(pid);
		if (process == NULL)
			process_type = PROCESS_TYPE_UNKNOWN;
		else {
			process_type = process->type;
			child_process_remove(pid);
		}
		abnormal_exit = TRUE;

		/* write errors to syslog */
		process_type_name = process_names[process_type];
		if (WIFEXITED(status)) {
			status = WEXITSTATUS(status);
			if (status == 0) {
				abnormal_exit = FALSE;
				if (process_type == PROCESS_TYPE_UNKNOWN) {
					i_error("unknown child %s exited "
						"successfully", dec2str(pid));
				}
			} else if (status == 1 &&
				   process_type == PROCESS_TYPE_SSL_PARAM) {
				/* kludgy. hide this failure. */
			} else if (status == FATAL_DEFAULT &&
				   process->seen_fatal) {
				/* the error was already logged. */
			} else {
				msg = get_exit_status_message(status,
							      process_type);
				msg = msg == NULL ? "" :
					t_strconcat(" (", msg, ")", NULL);
				str_printfa(str,
					    "child %s (%s) returned error %d%s",
					    dec2str(pid), process_type_name,
					    status, msg);
			}
		} else if (WIFSIGNALED(status)) {
			str_printfa(str, "child %s (%s) killed with signal %d",
				    dec2str(pid), process_type_name,
				    WTERMSIG(status));
			log_coredump(str, process_type, status);
		}

		if (str_len(str) > 0) {
			if (process != NULL && process->ip.family != 0) {
				if (!process->ip_changed)
					str_append(str, " (ip=");
				else
					str_append(str, " (latest ip=");
				str_printfa(str, "%s)",
					    net_ip2addr(&process->ip));
			}
			i_error("%s", str_c(str));
		}

		if (destroy_callbacks[process_type] != NULL) {
			destroy_callbacks[process_type](process, pid,
							abnormal_exit);
		}
	}

	if (pid == -1 && errno != EINTR && errno != ECHILD)
		i_warning("waitpid() failed: %m");
}

void child_process_set_destroy_callback(enum process_type type,
					child_process_destroy_callback_t *cb)
{
	i_assert(type < PROCESS_TYPE_MAX);

	destroy_callbacks[type] = cb;
}

void child_processes_init(void)
{
	processes = hash_table_create(default_pool, default_pool, 128, NULL, NULL);
	lib_signals_set_handler(SIGCHLD, TRUE, sigchld_handler, NULL);
}

void child_processes_flush(void)
{
	/* make sure we log if child processes died unexpectedly */
	sigchld_handler(NULL, NULL);
}

void child_processes_deinit(void)
{
	child_processes_flush();
	lib_signals_unset_handler(SIGCHLD, sigchld_handler, NULL);
	hash_table_destroy(&processes);
}
