#ifndef __USERDB_VPOPMAIL_H
#define __USERDB_VPOPMAIL_H

#include <stdio.h>
#include <vpopmail.h>
#include <vauth.h>

/* Limit user and domain to 80 chars each (+1 for \0). I wouldn't recommend
   raising this limit at least much, vpopmail is full of potential buffer
   overflows. */
#define VPOPMAIL_LIMIT 81

struct vqpasswd *vpopmail_lookup_vqp(const char *user,
				     char vpop_user[VPOPMAIL_LIMIT],
				     char vpop_domain[VPOPMAIL_LIMIT]);

#endif
