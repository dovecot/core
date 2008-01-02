/* Copyright (c) 2002-2008 Dovecot authors, see the included COPYING file */

#include "common.h"
#include "lib-signals.h"
#include "array.h"
#include "hash.h"
#include "env-util.h"
#include "syslog-util.h"
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
	return hash_lookup(processes, POINTER_CAST(pid));
}

void child_process_add(pid_t pid, struct child_process *process)
{
	hash_insert(processes, POINTER_CAST(pid), process);
}

void child_process_remove(pid_t pid)
{
	hash_remove(processes, POINTER_CAST(pid));
}

void child_process_init_env(ARRAY_TYPE(const_string) *env)
{
	int facility;

	t_array_init(env, 128);

	/* we'll log through master process */
	envarr_addb(env, "LOG_TO_MASTER");
	if (env_tz != NULL)
		envarr_add(env, "TZ", env_tz);

	if (settings_root == NULL ||
	    !syslog_facility_find(settings_root->defaults->syslog_facility,
				  &facility))
		facility = LOG_MAIL;
	envarr_addi(env, "SYSLOG_FACILITY", facility);

	if (settings_root != NULL && !settings_root->defaults->version_ignore)
		envarr_add(env, "DOVECOT_VERSION", PACKAGE_VERSION);
#ifdef DEBUG
	if (gdb) envarr_addb(env, "GDB");
#endif
}

void client_process_exec(const char *cmd, const char *title,
			 ARRAY_TYPE(const_string) *env)
{
	const char *executable, *p, **argv;

	/* very simple argument splitting. */
	if (*title == '\0')
		argv = t_strsplit(cmd, " ");
	else
		argv = t_strsplit(t_strconcat(cmd, " ", title, NULL), " ");

	executable = argv[0];

	/* hide the path, it's ugly */
	p = strrchr(argv[0], '/');
	if (p != NULL) argv[0] = p+1;

	(void)array_append_space(env); /* NULL-terminate */
	execve(executable, (char **)argv,
	       (char **)array_idx_modifiable(env, 0));
}

static const char *get_exit_status_message(enum fatal_exit_status status)
{
	switch (status) {
	case FATAL_LOGOPEN:
		return "Can't open log file";
	case FATAL_LOGWRITE:
		return "Can't write to log file";
	case FATAL_LOGERROR:
		return "Internal logging error";
	case FATAL_OUTOFMEM:
		return "Out of memory";
	case FATAL_EXEC:
		return "exec() failed";

	case FATAL_DEFAULT:
		return "Fatal failure";
	}

	return NULL;
}

static void sigchld_handler(int signo ATTR_UNUSED,
			    void *context ATTR_UNUSED)
{
	struct child_process *process;
	const char *process_type_name, *msg;
	enum process_type process_type;
	pid_t pid;
	int status;
	bool abnormal_exit;

	while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
		/* get the type and remove from hash */
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
				msg = get_exit_status_message(status);
				msg = msg == NULL ? "" :
					t_strconcat(" (", msg, ")", NULL);
				i_error("child %s (%s) returned error %d%s",
					dec2str(pid), process_type_name,
					status, msg);
			}
		} else if (WIFSIGNALED(status)) {
			i_error("child %s (%s) killed with signal %d",
				dec2str(pid), process_type_name,
				WTERMSIG(status));
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
	processes = hash_create(default_pool, default_pool, 128, NULL, NULL);
	lib_signals_set_handler(SIGCHLD, TRUE, sigchld_handler, NULL);
}

void child_processes_deinit(void)
{
	/* make sure we log if child processes died unexpectedly */
	sigchld_handler(SIGCHLD, NULL);
	lib_signals_unset_handler(SIGCHLD, sigchld_handler, NULL);
	hash_destroy(&processes);
}
