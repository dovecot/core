#ifndef __LIB_SIGNALS_H
#define __LIB_SIGNALS_H

extern int lib_signal_hup, lib_signal_kill;

void lib_init_signals(void (*sig_quit_handler) (int));

#endif
