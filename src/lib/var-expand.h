#ifndef __VAR_EXPAND_H
#define __VAR_EXPAND_H

/* Expand % variables in str:

    %u user or user@domain
    %h home
    %n user
    %d domain */
void var_expand(string_t *dest, const char *str,
		const char *user, const char *home);

#endif
