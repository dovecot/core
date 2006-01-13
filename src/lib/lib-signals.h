#ifndef __LIB_SIGNALS_H
#define __LIB_SIGNALS_H

#include <signal.h>

typedef void signal_handler_t(int signo, void *context);

/* Set signal handler for specific signal. If delayed is TRUE, the handler
   will be called later, ie. not as a real signal handler. If handler is NULL,
   the signal is ignored. */
void lib_signals_set_handler(int signo, bool delayed,
			     signal_handler_t *handler, void *context);
void lib_signals_unset_handler(int signo,
			       signal_handler_t *handler, void *context);

void lib_signals_init(void);
void lib_signals_deinit(void);

#endif
