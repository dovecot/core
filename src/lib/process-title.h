#ifndef PROCESS_TITLE_H
#define PROCESS_TITLE_H

/* Initialize title changing. */
void process_title_init(char **argv[]);

/* Change the process title if possible. */
void process_title_set(const char *title);
/* Free all memory used by process title hacks. This should be the last
   function called by the process, since it frees argv and environment. */
void process_title_deinit(void);

#endif
