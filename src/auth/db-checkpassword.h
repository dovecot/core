#ifndef CHECKPASSWORD_COMMON_H
#define CHECKPASSWORD_COMMON_H

#include "auth-request.h"
#include "lib-signals.h"
#include "buffer.h"
#include "str.h"
#include "ioloop.h"
#include "hash.h"
#include "env-util.h"
#include "safe-memset.h"
#include "child-wait.h"

#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>


struct chkpw_auth_request {
	int fd_out, fd_in;
	struct io *io_out, *io_in;
	pid_t pid;

	string_t *input_buf;
	char *password;
	unsigned int write_pos;

	struct auth_request *request;
	void *callback;
	void (*half_finish_callback)();
	void (*finish_callback)();
        int internal_failure_code;

	int exit_status;
	unsigned int exited:1;
};

enum checkpassword_sigchld_handler_result {
	SIGCHLD_RESULT_UNKNOWN_CHILD = -1,
	SIGCHLD_RESULT_DEAD_CHILD = -2,
	SIGCHLD_RESULT_UNKNOWN_ERROR = -3,
	SIGCHLD_RESULT_OK = 1,
};


void checkpassword_request_free(struct chkpw_auth_request *request);
enum checkpassword_sigchld_handler_result
checkpassword_sigchld_handler(const struct child_wait_status *child_wait_status,
			      struct chkpw_auth_request *request);
void checkpassword_setup_env(struct auth_request *request);
const char *
checkpassword_get_cmd(struct auth_request *request, const char *args,
		      const char *checkpassword_reply_path);

void checkpassword_child_input(struct chkpw_auth_request *request);
void checkpassword_child_output(struct chkpw_auth_request *request);

#endif
