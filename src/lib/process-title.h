#ifndef PROCESS_TITLE_H
#define PROCESS_TITLE_H

/* Initialize title changing. */
void process_title_init(int argc, char **argv[]);

/* Change the process title if possible. */
void process_title_set(const char *title);
/* Return the previously set process title. NULL means that it's either not
   set, or the title was explicitly set to NULL previously. */
const char *process_title_get(void);

/* Free all memory used by process title hacks. This should be the last
   function called by the process, since it frees argv and environment. */
void process_title_deinit(void);

#endif
