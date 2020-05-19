#ifndef LIB_SIGNALS_H
#define LIB_SIGNALS_H

#include <signal.h>

enum libsig_flags {
	/* Signal handler will be called later from IO loop when it's safe to
	   do any kind of work */
	LIBSIG_FLAG_DELAYED	= 0x01,
	/* Restart syscalls instead of having them fail with EINTR */
	LIBSIG_FLAG_RESTART	= 0x02,
	/* Automatically shift delayed signal handling for this signal
	   to a newly started ioloop. */
	LIBSIG_FLAG_IOLOOP_AUTOMOVE = 0x04,
};
#define LIBSIG_FLAGS_SAFE (LIBSIG_FLAG_DELAYED | LIBSIG_FLAG_RESTART)

typedef void signal_handler_t(const siginfo_t *si, void *context);

/* Number of times a "termination signal" has been received.
   These signals are SIGINT, SIGQUIT and SIGTERM. Callers can compare this to
   their saved previous value to see if a syscall returning EINTR should be
   treated as someone wanting to end the process or just some internal signal
   that should be ignored, such as SIGCHLD.

   This is marked as volatile so that compiler won't optimize away its
   comparisons. It may not work perfectly everywhere, such as when accessing it
   isn't atomic, so you shouldn't heavily rely on its actual value. */
extern volatile unsigned int signal_term_counter;

/* Convert si_code to string */
const char *lib_signal_code_to_str(int signo, int sicode);

/* Detach IOs from all ioloops. This isn't normally necessary, except when
   forking a process. */
void lib_signals_ioloop_detach(void);
void lib_signals_ioloop_attach(void);

/* Set signal handler for specific signal. */
void lib_signals_set_handler(int signo, enum libsig_flags flags,
			     signal_handler_t *handler, void *context)
	ATTR_NULL(4);
/* Ignore given signal. */
void lib_signals_ignore(int signo, bool restart_syscalls);
/* Clear all signal handlers for a specific signal and restore default system
   handler. */
void lib_signals_clear_handlers(int signo);
/* Unset specific signal handler for specific signal. */
void lib_signals_unset_handler(int signo,
			       signal_handler_t *handler, void *context)
	ATTR_NULL(3);

/* Indicate whether signals are expected for the indicated delayed handler. When
   signals are expected, the io for delayed handlers will be allowed to wait
   alone on the ioloop.  */
void lib_signals_set_expected(int signo, bool expected,
			      signal_handler_t *handler, void *context);
	ATTR_NULL(4);

/* Switch ioloop for a specific signal handler created with
   LIBSIG_FLAG_NO_IOLOOP_AUTOMOVE. */
void lib_signals_switch_ioloop(int signo,
			       signal_handler_t *handler, void *context);

/* Log a syscall error inside a (non-delayed) signal handler where i_error() is
   unsafe. errno number will be appended to the prefix. */
void lib_signals_syscall_error(const char *prefix);

void lib_signals_init(void);
void lib_signals_deinit(void);

#endif
