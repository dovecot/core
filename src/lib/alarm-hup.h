#ifndef __ALARM_HUP_H
#define __ALARM_HUP_H

/* Set new alarm() interval. Returns the old one. alarm() is called
   immediately with the specified timeout. */
unsigned int alarm_hup_set_interval(unsigned int timeout);

/* init() may be called multiple times. */
void alarm_hup_init(void);
void alarm_hup_deinit(void);

#endif
