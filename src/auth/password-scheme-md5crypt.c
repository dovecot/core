/*
 * ----------------------------------------------------------------------------
 * "THE BEER-WARE LICENSE" (Revision 42):
 * <phk@login.dknet.dk> wrote this file.  As long as you retain this notice you
 * can do whatever you want with this stuff. If we meet some day, and you think
 * this stuff is worth it, you can buy me a beer in return.   Poul-Henning Kamp
 * ----------------------------------------------------------------------------
 */

/*
 * Ported from FreeBSD to Linux, only minimal changes.  --marekm
 */

/*
 * Adapted from shadow-19990607 by Tudor Bosman, tudorb@jm.nu
 */

#include "lib.h"
#include "safe-memset.h"
#include "str.h"
#include "md5.h"
#include "password-scheme.h"

static unsigned char itoa64[] =		/* 0 ... 63 => ascii - 64 */
	"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

static char	magic[] = "$1$";	/*
				 * This string is magic for
				 * this algorithm.  Having
				 * it this way, we can get
				 * get better later on
				 */

static void
to64(string_t *str, unsigned long v, int n)
{
	while (--n >= 0) {
		str_append_c(str, itoa64[v&0x3f]);
		v >>= 6;
	}
}

/*
 * UNIX password
 *
 * Use MD5 for what it is best at...
 */

const char *password_generate_md5_crypt(const char *pw, const char *salt)
{
	const char *sp,*ep;
	unsigned char	final[MD5_RESULTLEN];
	int sl,pl,i,j;
	struct md5_context ctx,ctx1;
	unsigned long l;
	string_t *passwd;
	size_t pw_len = strlen(pw);

	/* Refine the Salt first */
	sp = salt;

	/* If it starts with the magic string, then skip that */
	if (strncmp(sp, magic, sizeof(magic)-1) == 0)
		sp += sizeof(magic)-1;

	/* It stops at the first '$', max 8 chars */
	for(ep=sp;*ep && *ep != '$' && ep < (sp+8);ep++)
		continue;

	/* get the length of the true salt */
	sl = ep - sp;

	md5_init(&ctx);

	/* The password first, since that is what is most unknown */
	md5_update(&ctx,pw,pw_len);

	/* Then our magic string */
	md5_update(&ctx,magic,sizeof(magic)-1);

	/* Then the raw salt */
	md5_update(&ctx,sp,sl);

	/* Then just as many characters of the MD5(pw,salt,pw) */
	md5_init(&ctx1);
	md5_update(&ctx1,pw,pw_len);
	md5_update(&ctx1,sp,sl);
	md5_update(&ctx1,pw,pw_len);
	md5_final(&ctx1,final);
	for(pl = pw_len; pl > 0; pl -= MD5_RESULTLEN)
		md5_update(&ctx,final,pl>MD5_RESULTLEN ? MD5_RESULTLEN : pl);

	/* Don't leave anything around in vm they could use. */
	safe_memset(final, 0, sizeof(final));

	/* Then something really weird... */
	for (j=0,i = pw_len; i ; i >>= 1)
		if(i&1)
		    md5_update(&ctx, final+j, 1);
		else
		    md5_update(&ctx, pw+j, 1);

	/* Now make the output string */
	passwd = t_str_new(sl + 64);
	str_append(passwd, magic);
	str_append_n(passwd, sp, sl);
	str_append_c(passwd, '$');

	md5_final(&ctx,final);

	/*
	 * and now, just to make sure things don't run too fast
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */
	for(i=0;i<1000;i++) {
		md5_init(&ctx1);
		if(i & 1)
			md5_update(&ctx1,pw,pw_len);
		else
			md5_update(&ctx1,final,MD5_RESULTLEN);

		if(i % 3)
			md5_update(&ctx1,sp,sl);

		if(i % 7)
			md5_update(&ctx1,pw,pw_len);

		if(i & 1)
			md5_update(&ctx1,final,MD5_RESULTLEN);
		else
			md5_update(&ctx1,pw,pw_len);
		md5_final(&ctx1,final);
	}

	l = (final[ 0]<<16) | (final[ 6]<<8) | final[12]; to64(passwd,l,4);
	l = (final[ 1]<<16) | (final[ 7]<<8) | final[13]; to64(passwd,l,4);
	l = (final[ 2]<<16) | (final[ 8]<<8) | final[14]; to64(passwd,l,4);
	l = (final[ 3]<<16) | (final[ 9]<<8) | final[15]; to64(passwd,l,4);
	l = (final[ 4]<<16) | (final[10]<<8) | final[ 5]; to64(passwd,l,4);
	l =                    final[11]                ; to64(passwd,l,2);

	/* Don't leave anything around in vm they could use. */
	safe_memset(final, 0, sizeof(final));

	return str_c(passwd);
}
