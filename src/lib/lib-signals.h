#ifndef __LIB_SIGNALS_H
#define __LIB_SIGNALS_H

extern int lib_signal_kill;
extern unsigned int lib_signal_hup_count;

void lib_init_signals(void (*sig_quit_handler) (int));

#endif
