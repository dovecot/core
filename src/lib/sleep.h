#ifndef SLEEP_H
#define SLEEP_H

/* Sleep for the indicated number of microseconds. Signal interruptions are
   handled and ignored internally. */
void i_sleep_usecs(unsigned long long usecs);
/* Sleep for the indicated number of milliseconds. Signal interruptions are
   handled and ignored internally. */
void i_sleep_msecs(unsigned int msecs);
/* Sleep for the indicated number of seconds. Signal interruptions are
   handled and ignored internally. */
void i_sleep_secs(time_t secs);

/* Sleep for the indicated number of microseconds while allowing signal
   interruptions. This function returns FALSE when it is interrupted by a
   signal. Otherwise, this function always returns TRUE. */
bool ATTR_NOWARN_UNUSED_RESULT
i_sleep_intr_usecs(unsigned long long usecs);
/* Sleep for the indicated number of milliseconds while allowing signal
   interruptions. This function returns FALSE when it is interrupted by a
   signal. Otherwise, this function always returns TRUE. */
bool ATTR_NOWARN_UNUSED_RESULT
i_sleep_intr_msecs(unsigned int msecs);
/* Sleep for the indicated number of seconds while allowing signal
   interruptions. This function returns FALSE when it is interrupted by a
   signal. Otherwise, this function always returns TRUE. */
bool ATTR_NOWARN_UNUSED_RESULT
i_sleep_intr_secs(time_t secs);

#endif
