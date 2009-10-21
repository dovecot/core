#ifndef PROCESS_TITLE_H
#define PROCESS_TITLE_H

/* Initialize title changing. */
void process_title_init(char **argv[], char *envp[]);

/* Change the process title if possible. */
void process_title_set(const char *title);

#endif
