/* Copyright (c) 2002-2017 Dovecot authors, see the included COPYING file
 */

#include "lib.h"
#include "lib-signals.h"
#include "env-util.h"
#include "execv-const.h"
#include "array.h"
#include "net.h"
#include "istream.h"
#include "ostream.h"
#include "restrict-access.h"
#include "child-wait.h"
#include "time-util.h"
#include "program-client-private.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#include <grp.h>

#define KILL_TIMEOUT 5000

struct program_client_local {
	struct program_client client;

	struct child_wait *child_wait;
	struct timeout *to_kill;

	pid_t pid;
	int status;
	bool exited:1;
	bool stopping:1;
	bool sent_term:1;
};

static
void program_client_local_waitchild(const struct child_wait_status *, struct program_client_local *);
static
void program_client_local_disconnect(struct program_client *pclient, bool force);
static
void program_client_local_exited(struct program_client_local *slclient);

static
void exec_child(const char *bin_path, const char *const *args, const char *const *envs,
		int in_fd, int out_fd, int *extra_fds, bool drop_stderr)
{
	ARRAY_TYPE(const_string) exec_args;

	/* Setup stdin/stdout */

	if (in_fd < 0)
		in_fd = dev_null_fd;
	if (out_fd < 0)
		out_fd = dev_null_fd;

	if (in_fd != STDIN_FILENO && dup2(in_fd, STDIN_FILENO) < 0)
		i_fatal("dup2(stdin) failed: %m");
	if (out_fd != STDOUT_FILENO && dup2(out_fd, STDOUT_FILENO) < 0)
		i_fatal("dup2(stdout) failed: %m");

	if (in_fd != STDIN_FILENO && in_fd != dev_null_fd && close(in_fd) < 0)
		i_error("close(in_fd) failed: %m");
	if (out_fd != STDOUT_FILENO && out_fd != dev_null_fd &&
	    (out_fd != in_fd) && close(out_fd) < 0)
		i_error("close(out_fd) failed: %m");

	/* Drop stderr if requested */
	if (drop_stderr) {
		if (dup2(dev_null_fd, STDERR_FILENO) < 0)
			i_fatal("dup2(stderr) failed: %m");
	}

	/* Setup extra fds */
	if (extra_fds != NULL) {
		int *efd;
		for(efd = extra_fds; *efd != -1; efd += 2) {
			i_assert(efd[1] != STDIN_FILENO);
			i_assert(efd[1] != STDOUT_FILENO);
			i_assert(efd[1] != STDERR_FILENO);
			if (efd[0] != efd[1]) {
				if (dup2(efd[0], efd[1]) < 0)
					i_fatal("dup2(extra_fd=%d) failed: %m",
						efd[1]);
			}
		}
		for(efd = extra_fds; *efd != -1; efd += 2) {
			if (efd[0] != efd[1] && efd[0] != STDIN_FILENO &&
			    efd[0] != STDOUT_FILENO &&
			    efd[0] != STDERR_FILENO) {
				if (close(efd[0]) < 0)
					i_error("close(extra_fd=%d) failed: %m",
						efd[1]);
			}
		}
	}

	/* Compose argv */

	t_array_init(&exec_args, 16);
	array_append(&exec_args, &bin_path, 1);
	if (args != NULL) {
		for(; *args != NULL; args++)
			array_append(&exec_args, args, 1);
	}
	(void) array_append_space(&exec_args);

	/* Setup environment */

	env_clean();
	if (envs != NULL) {
		for(; *envs != NULL; envs++)
			env_put(*envs);
	}

	/* Execute */

	args = array_idx(&exec_args, 0);
	execvp_const(args[0], args);
}

static
void program_client_local_waitchild(const struct child_wait_status *status,
				    struct program_client_local *slclient)
{
	i_assert(slclient->pid == status->pid);

	slclient->status = status->status;
	slclient->exited = TRUE;
	slclient->pid = -1;

	if (slclient->stopping)
		program_client_local_exited(slclient);
	else
		program_client_program_input(&slclient->client);
}

static
int program_client_local_connect(struct program_client *pclient)
{
	struct program_client_local *slclient = (struct program_client_local *) pclient;
	int fd_in[2] = { -1, -1 }, fd_out[2] = {-1, -1};
	struct program_client_extra_fd *efds = NULL;
	int *parent_extra_fds = NULL, *child_extra_fds = NULL;
	unsigned int xfd_count = 0, i;

	/* create normal I/O fds */
	if (pclient->input != NULL) {
		if (pipe(fd_in) < 0) {
			i_error("pipe(in) failed: %m");
			return -1;
		}
	}
	if (pclient->output != NULL || pclient->output_seekable) {
		if (pipe(fd_out) < 0) {
			i_error("pipe(out) failed: %m");
			return -1;
		}
	}

	/* create pipes for additional output through side-channel fds */
	if (array_is_created(&pclient->extra_fds)) {
		int extra_fd[2];

		efds = array_get_modifiable(&pclient->extra_fds, &xfd_count);
		if (xfd_count > 0) {
			i_assert(xfd_count < INT_MAX);
			parent_extra_fds = t_new(int, xfd_count);
			child_extra_fds = t_new(int, xfd_count * 2 + 1);
			for(i = 0; i < xfd_count; i++) {
				if (pipe(extra_fd) < 0) {
					i_error("pipe(extra=%d) failed: %m",
						extra_fd[1]);
					return -1;
				}
				parent_extra_fds[i] = extra_fd[0];
				child_extra_fds[i * 2 + 0] = extra_fd[1];
				child_extra_fds[i * 2 + 1] = efds[i].child_fd;
			}
			child_extra_fds[xfd_count * 2] = -1;
		}
	}

	/* fork child */
	if ((slclient->pid = fork()) == (pid_t)-1) {
		i_error("fork() failed: %m");

		/* clean up */
		if (fd_in[0] >= 0 && close(fd_in[0]) < 0) {
			i_error("close(pipe:in:rd) failed: %m");
		}
		if (fd_in[1] >= 0 && close(fd_in[1]) < 0) {
			i_error("close(pipe:in:wr) failed: %m");
		}
		if (fd_out[0] >= 0 && close(fd_out[0]) < 0) {
			i_error("close(pipe:out:rd) failed: %m");
		}
		if (fd_out[1] >= 0 && close(fd_out[1]) < 0) {
			i_error("close(pipe:out:wr) failed: %m");
		}
		for(i = 0; i < xfd_count; i++) {
			if (close(child_extra_fds[i * 2]) < 0) {
				i_error("close(pipe:extra=%d:wr) failed: %m",
					child_extra_fds[i * 2 + 1]);
			}
			if (close(parent_extra_fds[i]) < 0) {
				i_error("close(pipe:extra=%d:rd) failed: %m",
					child_extra_fds[i * 2 + 1]);
			}
		}
		return -1;
	}

	if (slclient->pid == 0) {
		unsigned int count;
		const char *const *envs = NULL;

		/* child */
		if (fd_in[1] >= 0 && close(fd_in[1]) < 0)
			i_error("close(pipe:in:wr) failed: %m");
		if (fd_out[0] >= 0 && close(fd_out[0]) < 0)
			i_error("close(pipe:out:rd) failed: %m");
		for(i = 0; i < xfd_count; i++) {
			if (close(parent_extra_fds[i]) < 0) {
				i_error("close(pipe:extra=%d:rd) failed: %m",
					child_extra_fds[i * 2 + 1]);
			}
		}

		/* if we want to allow root, then we will not drop
		   root privileges */
		pclient->set.restrict_set.drop_setuid_root =
			!pclient->set.allow_root;

		restrict_access(&pclient->set.restrict_set, pclient->set.home,
				!pclient->set.allow_root);

		if (array_is_created(&pclient->envs))
			envs = array_get(&pclient->envs, &count);

		exec_child(pclient->path, pclient->args, envs,
			   fd_in[0], fd_out[1], child_extra_fds,
			   pclient->set.drop_stderr);
		i_unreached();
	}

	/* parent */
	if (fd_in[0] >= 0 && close(fd_in[0]) < 0)
		i_error("close(pipe:in:rd) failed: %m");
	if (fd_out[1] >= 0 && close(fd_out[1]) < 0)
		i_error("close(pipe:out:wr) failed: %m");
	if (fd_in[1] >= 0) {
		net_set_nonblock(fd_in[1], TRUE);
		pclient->fd_out = fd_in[1];
	}
	if (fd_out[0] >= 0) {
		net_set_nonblock(fd_out[0], TRUE);
		pclient->fd_in = fd_out[0];
	}
	for(i = 0; i < xfd_count; i++) {
		if (close(child_extra_fds[i * 2]) < 0) {
			i_error("close(pipe:extra=%d:wr) failed: %m",
				child_extra_fds[i * 2 + 1]);
		}
		net_set_nonblock(parent_extra_fds[i], TRUE);
		efds[i].parent_fd = parent_extra_fds[i];
	}

	program_client_init_streams(pclient);

	slclient->child_wait = child_wait_new_with_pid(slclient->pid, program_client_local_waitchild,
				slclient);
	return program_client_connected(pclient);
}

static
int program_client_local_close_output(struct program_client *pclient)
{
	int fd_out = pclient->fd_out;

	pclient->fd_out = -1;

	/* Shutdown output; program stdin will get EOF */
	if (fd_out >= 0 && close(fd_out) < 0) {
		i_error("close(%s) failed: %m", pclient->path);
		return -1;
	}
	return 1;
}

static
void program_client_local_exited(struct program_client_local *slclient)
{
	if (slclient->to_kill != NULL)
		timeout_remove(&slclient->to_kill);
	if (slclient->child_wait != NULL)
		child_wait_free(&slclient->child_wait);

	struct program_client *pclient = &slclient->client;
	slclient->exited = TRUE;
	slclient->pid = -1;
	/* Evaluate child exit status */
	pclient->exit_code = -1;

	if (WIFEXITED(slclient->status)) {
		/* Exited */
		int exit_code = WEXITSTATUS(slclient->status);

		if (exit_code != 0) {
			i_info("program `%s' terminated with non-zero exit code %d",
			       pclient->path, exit_code);
			pclient->exit_code = 0;
		} else {
			pclient->exit_code = 1;
		}
	} else if (WIFSIGNALED(slclient->status)) {
		/* Killed with a signal */
		if (slclient->sent_term) {
			i_error("program `%s' was forcibly terminated with signal %d",
				pclient->path, WTERMSIG(slclient->status));
		} else {
			i_error("program `%s' terminated abnormally, signal %d",
				pclient->path, WTERMSIG(slclient->status));
		}
	} else if (WIFSTOPPED(slclient->status)) {
		/* Stopped */
		i_error("program `%s' stopped, signal %d",
			pclient->path, WSTOPSIG(slclient->status));
	} else {
		/* Something else */
		i_error("program `%s' terminated abnormally, return status %d",
			pclient->path, slclient->status);
	}

	program_client_disconnected(pclient);
}

static
void program_client_local_kill(struct program_client_local *slclient)
{
	/* time to die */
	if (slclient->to_kill != NULL)
		timeout_remove(&slclient->to_kill);

	i_assert(slclient->pid != (pid_t)-1);

	if (slclient->client.error == PROGRAM_CLIENT_ERROR_NONE)
		slclient->client.error = PROGRAM_CLIENT_ERROR_RUN_TIMEOUT;

	if (slclient->sent_term) {
		/* no need for this anymore */
		child_wait_free(&slclient->child_wait);

		/* Timed out again */
		if (slclient->client.debug) {
			i_debug("program `%s' (%d) did not die after %d milliseconds: "
				"sending KILL signal",
				slclient->client.path, slclient->pid, KILL_TIMEOUT);
		}

		/* Kill it brutally now, it should die right away */
		if (kill(slclient->pid, SIGKILL) < 0) {
			i_error("failed to send SIGKILL signal to program `%s'",
				slclient->client.path);
		} else if (waitpid(slclient->pid, &slclient->status, 0) < 0) {
			i_error("waitpid(%s) failed: %m",
				slclient->client.path);
		}
		program_client_local_exited(slclient);
		return;
	}

	if (slclient->client.debug)
		i_debug("program `%s'(%d) execution timed out after %u milliseconds: "
			"sending TERM signal", slclient->client.path, slclient->pid,
			slclient->client.set.input_idle_timeout_msecs);

	/* send sigterm, keep on waiting */
	slclient->sent_term = TRUE;

	/* Kill child gently first */
	if (kill(slclient->pid, SIGTERM) < 0) {
		i_error("failed to send SIGTERM signal to program `%s'",
			slclient->client.path);
		(void)kill(slclient->pid, SIGKILL);
		program_client_local_exited(slclient);
		return;
	}

	i_assert(slclient->child_wait != NULL);

	slclient->to_kill = timeout_add_short(KILL_TIMEOUT,
			    program_client_local_kill, slclient);
}

static
void program_client_local_disconnect(struct program_client *pclient, bool force)
{
	struct program_client_local *slclient =
		(struct program_client_local *) pclient;
	pid_t pid = slclient->pid;
	unsigned long runtime, timeout = 0;

	if (slclient->exited) {
		program_client_local_exited(slclient);
		return;
	}

	if (slclient->stopping) return;
	slclient->stopping = TRUE;

	if (pid < 0) {
		/* program never started */
		pclient->exit_code = 0;
		program_client_local_exited(slclient);
		return;
	}

	/* make sure it hasn't already been reaped */
	if (waitpid(slclient->pid, &slclient->status, WNOHANG) > 0) {
		program_client_local_exited(slclient);
		return;
	}

	/* Calculate timeout */
	runtime = timeval_diff_msecs(&ioloop_timeval, &pclient->start_time);
	if (!force && pclient->set.input_idle_timeout_msecs > 0 &&
	    runtime < pclient->set.input_idle_timeout_msecs)
		timeout = pclient->set.input_idle_timeout_msecs - runtime;

	if (pclient->debug) {
		i_debug("waiting for program `%s' to finish after %lu msecs",
			pclient->path, runtime);
	}

	force = force ||
		(timeout == 0 && pclient->set.input_idle_timeout_msecs > 0);

	if (!force) {
		if (timeout > 0)
			slclient->to_kill =
				timeout_add_short(timeout,
						  program_client_local_kill,
						  slclient);
	} else {
		program_client_local_kill(slclient);
	}
}

static
void program_client_local_destroy(struct program_client *pclient ATTR_UNUSED)
{
	child_wait_deinit();
}

static
void program_client_local_switch_ioloop(struct program_client *pclient)
{
	struct program_client_local *slclient =
		(struct program_client_local *)pclient;

	if (slclient->to_kill != NULL)
		slclient->to_kill = io_loop_move_timeout(&slclient->to_kill);
	lib_signals_reset_ioloop();
}

struct program_client *
program_client_local_create(const char *bin_path,
			    const char *const *args,
			    const struct program_client_settings *set)
{
	struct program_client_local *pclient;
	pool_t pool;

	pool = pool_alloconly_create("program client local", 1024);
	pclient = p_new(pool, struct program_client_local, 1);
	program_client_init(&pclient->client, pool, bin_path, args, set);
	pclient->client.connect = program_client_local_connect;
	pclient->client.close_output = program_client_local_close_output;
	pclient->client.switch_ioloop = program_client_local_switch_ioloop;
	pclient->client.disconnect = program_client_local_disconnect;
	pclient->client.destroy = program_client_local_destroy;
	pclient->pid = -1;
	child_wait_init();

	return &pclient->client;
}
