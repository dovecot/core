/* Copyright (C) 2002 Timo Sirainen */

#include "common.h"
#include "network.h"
#include "obuffer.h"
#include "fdpass.h"
#include "restrict-access.h"
#include "login-process.h"
#include "auth-process.h"
#include "master-interface.h"

#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>

typedef struct {
	int refcount;

	pid_t pid;
	int fd;
	IO io;
	OBuffer *outbuf;
	unsigned int destroyed:1;
} LoginProcess;

typedef struct {
	LoginProcess *process;
	int login_id;
	int auth_id;
	int fd;

	char login_tag[LOGIN_TAG_SIZE];
} LoginAuthRequest;

static int auth_id_counter;
static Timeout to;
static HashTable *processes = NULL;

static void login_process_destroy(LoginProcess *p);
static void login_process_unref(LoginProcess *p);

static void auth_callback(AuthCookieReplyData *cookie_reply, void *context)
{
	const char *env[] = {
		"MAIL", NULL,
		"LOGIN_TAG", NULL,
		NULL
	};
	LoginAuthRequest *request = context;
        LoginProcess *process;
	MasterReply reply;

	env[1] = cookie_reply->mail;
	env[3] = request->login_tag;

	if (cookie_reply == NULL || !cookie_reply->success)
		reply.result = MASTER_RESULT_FAILURE;
	else {
		reply.result = create_imap_process(request->fd,
						   cookie_reply->user,
						   cookie_reply->uid,
						   cookie_reply->gid,
						   cookie_reply->home,
						   cookie_reply->chroot, env);
	}

	/* reply to login */
	reply.id = request->login_id;

	process = request->process;
	if (o_buffer_send(process->outbuf, &reply, sizeof(reply)) < 0)
		login_process_destroy(process);

	(void)close(request->fd);
	login_process_unref(process);
	i_free(request);
}

static void login_process_input(void *context, int fd __attr_unused__,
				IO io __attr_unused__)
{
	LoginProcess *p = context;
	AuthProcess *auth_process;
	LoginAuthRequest *authreq;
	MasterRequest req;
	int client_fd, ret;

	ret = fd_read(p->fd, &req, sizeof(req), &client_fd);
	if (ret != sizeof(req)) {
		if (ret == 0) {
			/* disconnected, ie. the login process died */
		} else if (ret > 0) {
			/* req wasn't fully read */
			i_error("login: fd_read() couldn't read all req");
		} else {
			i_error("login: fd_read() failed: %m");
		}

		login_process_destroy(p);
		return;
	}

	/* login process isn't trusted, validate all data to make sure
	   it's not trying to exploit us */
	if (!VALIDATE_STR(req.login_tag)) {
		i_error("login: Received corrupted data");
		login_process_destroy(p);
		return;
	}

	/* ask the cookie from the auth process */
	authreq = i_new(LoginAuthRequest, 1);
	p->refcount++;
	authreq->process = p;
	authreq->login_id = req.id;
	authreq->auth_id = ++auth_id_counter;
	authreq->fd = client_fd;
	strcpy(authreq->login_tag, req.login_tag);

	auth_process = auth_process_find(req.auth_process);
	if (auth_process == NULL) {
		i_error("login: Authentication process %u doesn't exist",
			req.auth_process);
		auth_callback(NULL, &authreq);
	} else {
		auth_process_request(auth_process, authreq->auth_id, req.cookie,
				     auth_callback, authreq);
	}
}

static LoginProcess *login_process_new(pid_t pid, int fd)
{
	LoginProcess *p;

	PID_ADD_PROCESS_TYPE(pid, PROCESS_TYPE_LOGIN);

	p = i_new(LoginProcess, 1);
	p->refcount = 1;
	p->pid = pid;
	p->fd = fd;
	p->io = io_add(fd, IO_READ, login_process_input, p);
	p->outbuf = o_buffer_create_file(fd, default_pool,
					 sizeof(MasterReply)*10,
					 IO_PRIORITY_DEFAULT, FALSE);

	hash_insert(processes, POINTER_CAST(pid), p);
	return p;
}

static void login_process_destroy(LoginProcess *p)
{
	if (p->destroyed)
		return;
	p->destroyed = TRUE;

	o_buffer_close(p->outbuf);
	io_remove(p->io);
	(void)close(p->fd);

	hash_remove(processes, POINTER_CAST(p->pid));
	login_process_unref(p);
}

static void login_process_unref(LoginProcess *p)
{
	if (--p->refcount > 0)
		return;

	o_buffer_unref(p->outbuf);
	i_free(p);
}

static pid_t create_login_process(void)
{
	static const char *argv[] = { NULL, NULL };
	pid_t pid;
	int fd[2];

	if (set_login_uid == 0)
		i_fatal("Login process must not run as root");

	/* create communication to process with a socket pair */
	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fd) == -1) {
		i_error("socketpair() failed: %m");
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		(void)close(fd[0]);
		(void)close(fd[1]);
		i_error("fork() failed: %m");
		return -1;
	}

	if (pid != 0) {
		/* master */
		login_process_new(pid, fd[0]);
		(void)close(fd[1]);
		return pid;
	}

	/* move communication handle */
	if (dup2(fd[1], LOGIN_MASTER_SOCKET_FD) < 0)
		i_fatal("login: dup2() failed: %m");

	/* move the listen handle */
	if (dup2(imap_fd, LOGIN_IMAP_LISTEN_FD) < 0)
		i_fatal("login: dup2() failed: %m");

	/* move the SSL listen handle */
	if (dup2(imaps_fd, LOGIN_IMAPS_LISTEN_FD) < 0)
		i_fatal("login: dup2() failed: %m");

	/* imap_fd and imaps_fd are closed by clean_child_process() */

	(void)close(fd[0]);
	(void)close(fd[1]);

	clean_child_process();

	/* setup access environment - needs to be done after
	   clean_child_process() since it clears environment */
	restrict_access_set_env(set_login_user, set_login_uid, set_login_gid,
				set_login_chroot ? set_login_dir : NULL);

	if (!set_login_chroot) {
		/* no chrooting, but still change to the directory */
		if (chdir(set_login_dir) < 0) {
			i_fatal("chdir(%s) failed: %m",
				set_login_dir);
		}
	}

	if (set_ssl_cert_file != NULL) {
		putenv((char *) t_strconcat("SSL_CERT_FILE=",
					    set_ssl_cert_file, NULL));
	}

	if (set_ssl_key_file != NULL) {
		putenv((char *) t_strconcat("SSL_KEY_FILE=",
					    set_ssl_key_file, NULL));
	}

	if (set_disable_plaintext_auth)
		putenv("DISABLE_PLAINTEXT_AUTH=1");

	putenv((char *) t_strdup_printf("MAX_LOGGING_USERS=%d",
					set_max_logging_users));

	/* hide the path, it's ugly */
	argv[0] = strrchr(set_login_executable, '/');
	if (argv[0] == NULL) argv[0] = set_login_executable; else argv[0]++;

	execv(set_login_executable, (char **) argv);

	i_fatal("execv(%s) failed: %m", argv[0]);
	return -1;
}

static void login_hash_cleanup(void *key __attr_unused__, void *value,
			       void *context __attr_unused__)
{
	LoginProcess *p = value;

	(void)close(p->fd);
}

void login_processes_cleanup(void)
{
	hash_foreach(processes, login_hash_cleanup, NULL);
}

static void login_processes_start_missing(void *context __attr_unused__,
					  Timeout timeout __attr_unused__)
{
	/* create max. one process every second, that way if it keeps
	   dying all the time we don't eat all cpu with fork()ing. */
	if (hash_size(processes) < set_login_processes_count)
                (void)create_login_process();
}

void login_processes_init(void)
{
        auth_id_counter = 0;
        processes = hash_create(default_pool, 128, NULL, NULL);
	to = timeout_add(1000, login_processes_start_missing, NULL);
}

static void login_hash_destroy(void *key __attr_unused__, void *value,
			       void *context __attr_unused__)
{
	login_process_destroy(value);
}

void login_processes_deinit(void)
{
	timeout_remove(to);

	hash_foreach(processes, login_hash_destroy, NULL);
	hash_destroy(processes);
}
