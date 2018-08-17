/* Copyright (c) 2001-2018 Dovecot authors, see the included COPYING file */

#include "lib.h"
#include "array.h"
#include "ioloop.h"
#include "write-full.h"
#include "lib-signals.h"

#include <stdio.h>
#include <signal.h>
#include <unistd.h>

#define MAX_SIGNAL_VALUE 63

#define SIGNAL_IS_TERMINAL(signo) \
	((signo) == SIGINT || (signo) == SIGQUIT || (signo) == SIGTERM)

#if !defined(SA_SIGINFO) && !defined(SI_NOINFO)
/* without SA_SIGINFO we don't know what the real code is. we need SI_NOINFO
   to make sure lib_signal_code_to_str() returns "". */
#  define SI_NOINFO -1
#endif

struct signal_handler {
	signal_handler_t *handler;
	void *context;

	enum libsig_flags flags;
	struct signal_handler *next;
	struct ioloop *current_ioloop;

	bool shadowed:1;
};

volatile unsigned int signal_term_counter = 0;

/* Remember that these are accessed inside signal handler which may be called
   even while we're initializing/deinitializing. Try hard to keep everything
   in consistent state. */
static struct signal_handler *signal_handlers[MAX_SIGNAL_VALUE+1] = { NULL, };
static int sig_pipe_fd[2] = { -1, -1 };

static bool signals_initialized = FALSE;
static struct io *io_sig = NULL;

static siginfo_t pending_signals[MAX_SIGNAL_VALUE+1];
static ARRAY(siginfo_t) pending_shadowed_signals;
static bool have_pending_signals = FALSE;
static bool ioloop_attached = FALSE;
static bool ioloop_switched = FALSE;

const char *lib_signal_code_to_str(int signo, int sicode)
{
	/* common */
	switch (sicode) {
#ifdef SI_NOINFO
	case SI_NOINFO:
		return "";
#endif
	case SI_USER:
		return "kill";
#ifdef SI_KERNEL
	case SI_KERNEL:
		return "kernel";
#endif
	case SI_TIMER:
		return "timer";
	}

	/* If SEGV_MAPERR is supported, the rest of them must be too.
	   FreeBSD 6 at least doesn't support these. */
#ifdef SEGV_MAPERR
	switch (signo) {
	case SIGSEGV:
		switch (sicode) {
		case SEGV_MAPERR:
			return "address not mapped";
		case SEGV_ACCERR:
			return "invalid permissions";
		}
		break;
	case SIGBUS:
		switch (sicode) {
		case BUS_ADRALN:
			return "invalid address alignment";
#ifdef BUS_ADRERR /* for OSX 10.3 */
		case BUS_ADRERR:
			return "nonexistent physical address";
#endif
#ifdef BUS_OBJERR /* for OSX 10.3 */
		case BUS_OBJERR:
			return "object-specific hardware error";
#endif
		}
	}
#endif
	return t_strdup_printf("unknown %d", sicode);
}

#ifdef SA_SIGINFO
static void sig_handler(int signo, siginfo_t *si, void *context ATTR_UNUSED)
#else
static void sig_handler(int signo)
#endif
{
	struct signal_handler *h;
	int saved_errno;
	char c = 0;

#if defined(SI_NOINFO) || !defined(SA_SIGINFO)
#ifndef SA_SIGINFO
	siginfo_t *si = NULL;
#endif
	siginfo_t tmp_si;

	if (si == NULL) {
		/* Solaris can leave this to NULL */
		i_zero(&tmp_si);
		tmp_si.si_signo = signo;
		tmp_si.si_code = SI_NOINFO;
		si = &tmp_si;
	}
#endif

	if (signo < 0 || signo > MAX_SIGNAL_VALUE)
		return;

	if (SIGNAL_IS_TERMINAL(signo))
		signal_term_counter++;

	/* remember that we're inside a signal handler which might have been
	   called at any time. don't do anything that's unsafe. we might also
	   get interrupted by another signal while inside this handler. */
	saved_errno = errno;
	for (h = signal_handlers[signo]; h != NULL; h = h->next) {
		if ((h->flags & LIBSIG_FLAG_DELAYED) == 0)
			h->handler(si, h->context);
		else if (pending_signals[signo].si_signo == 0) {
			pending_signals[signo] = *si;
			if (!have_pending_signals) {
				if (write(sig_pipe_fd[1], &c, 1) != 1)
					lib_signals_syscall_error("signal: write(sigpipe) failed: ");
				have_pending_signals = TRUE;
			}
		}
	}
	errno = saved_errno;
}

#ifdef SA_SIGINFO
static void sig_ignore(int signo ATTR_UNUSED, siginfo_t *si ATTR_UNUSED,
		       void *context ATTR_UNUSED)
#else
static void sig_ignore(int signo ATTR_UNUSED)
#endif
{
	/* if we used SIG_IGN instead of this function,
	   the system call might be restarted */
}

static void
signal_handle_shadowed(void)
{
	const	siginfo_t *sis;
	unsigned int count, i;

	if (!array_is_created(&pending_shadowed_signals) ||
		array_count(&pending_shadowed_signals) == 0)
		return;

	sis = array_get(&pending_shadowed_signals, &count);
	for (i = 0; i < count; i++) {
		struct signal_handler *h;
		bool shadowed = FALSE;

		i_assert(sis[i].si_signo > 0);
		for (h = signal_handlers[sis[i].si_signo]; h != NULL; h = h->next) {
			if ((h->flags & LIBSIG_FLAG_DELAYED) == 0 ||
				(h->flags & LIBSIG_FLAG_NO_IOLOOP_AUTOMOVE) == 0)
				continue;
			if (h->shadowed && h->current_ioloop != current_ioloop) {
				shadowed = TRUE;
				continue;
			}
			/* handler can be called now */
			h->shadowed = FALSE;
			h->handler(&sis[i], h->context);
		}
		if (!shadowed) {
			/* no handlers are shadowed anymore; delete the signal info */
			array_delete(&pending_shadowed_signals, i, 1);
			sis = array_get(&pending_shadowed_signals, &count);
		}
	}
}

static void
signal_check_shadowed(void)
{
	if (!array_is_created(&pending_shadowed_signals) ||
		array_count(&pending_shadowed_signals) == 0)
		return;

	if (io_sig != NULL)
		io_set_pending(io_sig);
}

static void
signal_shadow(int signo, const siginfo_t *si)
{
	const	siginfo_t *sis;
	unsigned int count, i;

	/* remember last signal info for handlers that cannot run in
	   current ioloop */
	if (!array_is_created(&pending_shadowed_signals))
		i_array_init(&pending_shadowed_signals, 4);
	sis = array_get(&pending_shadowed_signals, &count);
	for (i = 0; i < count; i++) {
		i_assert(sis[i].si_signo != 0);
		if (sis[i].si_signo == signo)
			break;
	}
	array_idx_set(&pending_shadowed_signals, i, si);
}

static void ATTR_NULL(1)
signal_read(void *context ATTR_UNUSED)
{
	siginfo_t signals[MAX_SIGNAL_VALUE+1];
	sigset_t fullset, oldset;
	struct signal_handler *h;
	char buf[64];
	int signo;
	ssize_t ret;

	if (ioloop_switched) {
		ioloop_switched = FALSE;
		/* handle any delayed signal handlers that emerged from the shadow */
		signal_handle_shadowed();
	}

	if (sigfillset(&fullset) < 0)
		i_fatal("sigfillset() failed: %m");
	if (sigprocmask(SIG_BLOCK, &fullset, &oldset) < 0)
		i_fatal("sigprocmask() failed: %m");

	/* typically we should read only a single byte, but if a signal
	   is sent while signal handler is running we might get more. */
	ret = read(sig_pipe_fd[0], buf, sizeof(buf));
	if (ret > 0) {
		memcpy(signals, pending_signals, sizeof(signals));
		memset(pending_signals, 0, sizeof(pending_signals));
		have_pending_signals = FALSE;
	} else if (ret < 0) {
		if (errno != EAGAIN)
			i_fatal("read(sigpipe) failed: %m");
	} else {
		i_fatal("read(sigpipe) failed: EOF");
	}
	if (sigprocmask(SIG_SETMASK, &oldset, NULL) < 0)
		i_fatal("sigprocmask() failed: %m");

	if (ret < 0)
		return;

	/* call the delayed handlers after signals are copied and unblocked */
	for (signo = 0; signo < MAX_SIGNAL_VALUE; signo++) {
		bool shadowed = FALSE;

		if (signals[signo].si_signo == 0)
			continue;

		for (h = signal_handlers[signo]; h != NULL; h = h->next) {
			if ((h->flags & LIBSIG_FLAG_DELAYED) == 0) {
				/* handler already called immediately in signal context */
				continue;
			}
			if ((h->flags & LIBSIG_FLAG_NO_IOLOOP_AUTOMOVE) != 0 &&
				h->current_ioloop != current_ioloop) {
				/* cannot run handler in current ioloop (shadowed) */
				h->shadowed = TRUE;
				shadowed = TRUE;
				continue;
			}
			/* handler can be called now */
			h->handler(&signals[signo], h->context);
		}

		if (shadowed) {
			/* remember last signal info for handlers that cannot run in
			   current ioloop (shadowed) */
			signal_shadow(signo, &signals[signo]);
		}
	}
}

static void
lib_signals_enable_delayed_hander(void)
{
	if (current_ioloop != NULL) {
		io_sig = io_add(sig_pipe_fd[0], IO_READ,
			signal_read, (void *)NULL);
		io_set_never_wait_alone(io_sig, TRUE);
	}
}

static void
lib_signals_disable_delayed_hander(void)
{
	if (io_sig != NULL)
		io_remove(&io_sig);
}

static void
lib_signals_ioloop_switched(struct ioloop *prev_ioloop ATTR_UNUSED)
{
	ioloop_switched = TRUE;

	lib_signals_disable_delayed_hander();
	lib_signals_enable_delayed_hander();

	/* check whether we can now handle any shadowed delayed signals */
	signal_check_shadowed();
}

void lib_signals_ioloop_detach(void)
{
	if (!ioloop_attached) {
		i_assert(io_sig == NULL);
		return;
	}
	ioloop_attached = FALSE;

	lib_signals_disable_delayed_hander();
	io_loop_remove_switch_callback(lib_signals_ioloop_switched);
}

void lib_signals_ioloop_attach(void)
{
	if (ioloop_attached)
		return;
	ioloop_attached = TRUE;

	lib_signals_disable_delayed_hander();
	lib_signals_enable_delayed_hander();
	io_loop_add_switch_callback(lib_signals_ioloop_switched);
}

static void lib_signals_set(int signo, enum libsig_flags flags)
{
	struct sigaction act;

	if (sigemptyset(&act.sa_mask) < 0)
		i_fatal("sigemptyset(): %m");
#ifdef SA_SIGINFO
	act.sa_flags = SA_SIGINFO;
	act.sa_sigaction = sig_handler;
#else
	act.sa_flags = 0;
	act.sa_handler = sig_handler;
#endif
	if ((flags & LIBSIG_FLAG_RESTART) != 0)
		act.sa_flags |= SA_RESTART;
	if (sigaction(signo, &act, NULL) < 0)
		i_fatal("sigaction(%d): %m", signo);
}

void lib_signals_set_handler(int signo, enum libsig_flags flags,
			     signal_handler_t *handler, void *context)
{
	struct signal_handler *h;

	i_assert(handler != NULL);

	if (signo < 0 || signo > MAX_SIGNAL_VALUE) {
		i_panic("Trying to set signal %d handler, but max is %d",
			signo, MAX_SIGNAL_VALUE);
	}

	if (signal_handlers[signo] == NULL && signals_initialized)
		lib_signals_set(signo, flags);

	h = i_new(struct signal_handler, 1);
	h->handler = handler;
	h->context = context;
	h->flags = flags;
	h->current_ioloop = current_ioloop;

	/* atomically set to signal_handlers[] list */
	h->next = signal_handlers[signo];
	signal_handlers[signo] = h;

	if ((flags & LIBSIG_FLAG_DELAYED) != 0 && sig_pipe_fd[0] == -1) {
		/* first delayed handler */
		if (pipe(sig_pipe_fd) < 0)
			i_fatal("pipe() failed: %m");
		fd_set_nonblock(sig_pipe_fd[0], TRUE);
		fd_set_nonblock(sig_pipe_fd[1], TRUE);
		fd_close_on_exec(sig_pipe_fd[0], TRUE);
		fd_close_on_exec(sig_pipe_fd[1], TRUE);
		if (signals_initialized)
			lib_signals_ioloop_attach();
	}
}

void lib_signals_ignore(int signo, bool restart_syscalls)
{
	struct sigaction act;

	if (signo < 0 || signo > MAX_SIGNAL_VALUE) {
		i_panic("Trying to ignore signal %d, but max is %d",
			signo, MAX_SIGNAL_VALUE);
	}

	i_assert(signal_handlers[signo] == NULL);

	if (sigemptyset(&act.sa_mask) < 0)
		i_fatal("sigemptyset(): %m");
	if (restart_syscalls) {
		act.sa_flags = SA_RESTART;
		act.sa_handler = SIG_IGN;
	} else {
#ifdef SA_SIGINFO
		act.sa_flags = SA_SIGINFO;
		act.sa_sigaction = sig_ignore;
#else
		act.sa_flags = 0;
		act.sa_handler = sig_ignore;
#endif
	}

	if (sigaction(signo, &act, NULL) < 0)
		i_fatal("sigaction(%d): %m", signo);
}

void lib_signals_unset_handler(int signo, signal_handler_t *handler,
			       void *context)
{
	struct signal_handler *h, **p;

	for (p = &signal_handlers[signo]; *p != NULL; p = &(*p)->next) {
		if ((*p)->handler == handler && (*p)->context == context) {
			h = *p;
			*p = h->next;
			i_free(h);
			return;
		}
	}

	i_panic("lib_signals_unset_handler(%d, %p, %p): handler not found",
		signo, (void *)handler, context);
}

void lib_signals_switch_ioloop(int signo,
	signal_handler_t *handler, void *context)
{
	struct signal_handler *h;

	for (h = signal_handlers[signo]; h != NULL; h = h->next) {
		if (h->handler == handler && h->context == context) {
			i_assert((h->flags & LIBSIG_FLAG_DELAYED) != 0);
			i_assert((h->flags & LIBSIG_FLAG_NO_IOLOOP_AUTOMOVE) != 0);
			h->current_ioloop = current_ioloop;
			/* check whether we can now handle any shadowed delayed signals */
			signal_check_shadowed();
			return;
		}
	}

	i_panic("lib_signals_switch_ioloop(%d, %p, %p): handler not found",
		signo, (void *)handler, context);
}

void lib_signals_syscall_error(const char *prefix)
{
	/* @UNSAFE: We're in a signal handler. It's very limited what is
	   allowed in here. Especially strerror() isn't at least officially
	   allowed. */
	char errno_buf[MAX_INT_STRLEN], *errno_str;
	errno_str = dec2str_buf(errno_buf, errno);

	size_t prefix_len = strlen(prefix);
	size_t errno_str_len = strlen(errno_str);
	char buf[prefix_len + errno_str_len + 1];

	memcpy(buf, prefix, prefix_len);
	memcpy(buf + prefix_len, errno_str, errno_str_len);
	buf[prefix_len + errno_str_len] = '\n';
	if (write_full(STDERR_FILENO, buf, prefix_len + errno_str_len + 1) < 0) {
		/* can't really do anything */
	}
}

void lib_signals_init(void)
{
	int i;

	signals_initialized = TRUE;

	/* add signals that were already registered */
	for (i = 0; i < MAX_SIGNAL_VALUE; i++) {
		if (signal_handlers[i] != NULL)
			lib_signals_set(i, signal_handlers[i]->flags);
	}

	if (sig_pipe_fd[0] != -1)
		lib_signals_ioloop_attach();
}

void lib_signals_deinit(void)
{
	struct signal_handler *handlers, *h;
	int i;

	for (i = 0; i < MAX_SIGNAL_VALUE; i++) {
		if (signal_handlers[i] != NULL) {
			/* atomically remove from signal_handlers[] list */
			handlers = signal_handlers[i];
			signal_handlers[i] = NULL;

			while (handlers != NULL) {
				h = handlers;
				handlers = h->next;
				i_free(h);
			}
		}
	}

	lib_signals_ioloop_detach();

	if (sig_pipe_fd[0] != -1) {
		if (close(sig_pipe_fd[0]) < 0)
			i_error("close(sigpipe) failed: %m");
		if (close(sig_pipe_fd[1]) < 0)
			i_error("close(sigpipe) failed: %m");
		sig_pipe_fd[0] = sig_pipe_fd[1] = -1;
	}

	if (array_is_created(&pending_shadowed_signals))
		array_free(&pending_shadowed_signals);
}
