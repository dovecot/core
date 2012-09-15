/* simple checkpassword wrapper to send userdb data back to dovecot-auth */

#include "lib.h"
#include "str.h"
#include "strescape.h"
#include "write-full.h"

#include <stdlib.h>
#include <unistd.h>

int main(void)
{
	string_t *str;
	const char *user, *home, *authorized;
	const char *extra_env, *key, *value, *const *tmp;
	bool uid_found = FALSE, gid_found = FALSE;

	lib_init();
	str = t_str_new(1024);

	user = getenv("USER");
	if (user != NULL) {
		if (strchr(user, '\t') != NULL) {
			i_error("checkpassword: USER contains TAB");
			return 1;
		}
		str_printfa(str, "user=");
		str_append_tabescaped(str, user);
		str_append_c(str, '\t');
	}

	home = getenv("HOME");
	if (home != NULL) {
		if (strchr(home, '\t') != NULL) {
			i_error("checkpassword: HOME contains TAB");
			return 1;
		}
		str_printfa(str, "userdb_home=");
		str_append_tabescaped(str, home);
		str_append_c(str, '\t');
	}

	extra_env = getenv("EXTRA");
	if (extra_env != NULL) {
		for (tmp = t_strsplit(extra_env, " "); *tmp != NULL; tmp++) {
			value = getenv(*tmp);
			if (value != NULL) {
				key = t_str_lcase(*tmp);
				if (strcmp(key, "userdb_uid") == 0)
					uid_found = TRUE;
				else if (strcmp(key, "userdb_gid") == 0)
					gid_found = TRUE;
				str_append_tabescaped(str, key);
				str_append_c(str, '=');
				str_append_tabescaped(str, value);
				str_append_c(str, '\t');
			}
		}
	}
	if (!uid_found)
		str_printfa(str, "userdb_uid=%s\t",  dec2str(getuid()));
	if (!gid_found)
		str_printfa(str, "userdb_gid=%s\t",  dec2str(getgid()));

	i_assert(str_len(str) > 0);

	if (write_full(4, str_data(str), str_len(str)) < 0) {
		i_error("checkpassword: write_full() failed: %m");
		exit(111);
	}
	authorized = getenv("AUTHORIZED");
	if (authorized == NULL) {
		/* authentication */
		return 0;
	} else if (strcmp(authorized, "2") == 0) {
		/* successful passdb/userdb lookup */
		return 2;
	} else {
		i_error("checkpassword: Script doesn't support passdb/userdb lookup");
		return 111;
	}
}
