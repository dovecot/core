#ifndef __LIB_SIGNALS_H
#define __LIB_SIGNALS_H

extern int lib_signal_kill;
extern unsigned int lib_signal_hup_count;
extern unsigned int lib_signal_usr1_count, lib_signal_usr2_count;

void lib_init_signals(void (*sig_quit_handler) (int));

#endif
