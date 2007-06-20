#include "common.h"
#include "capabilities.h"

#ifdef HAVE_LIBCAP

#include <sys/capability.h>

void drop_capabilities(void)
{
	/* the capabilities that we *need* in order to operate */
	static cap_value_t suidcaps[] = {
		CAP_CHOWN,
		CAP_SYS_CHROOT,
		CAP_SETUID,
		CAP_SETGID,
		CAP_NET_BIND_SERVICE
	};
	cap_t caps;

	caps = cap_init();
	cap_clear(caps);
	cap_set_flag(caps, CAP_PERMITTED,
		     sizeof(suidcaps) / sizeof(cap_value_t), suidcaps, CAP_SET);
	cap_set_flag(caps, CAP_EFFECTIVE,
		     sizeof(suidcaps) / sizeof(cap_value_t), suidcaps, CAP_SET);
	cap_set_proc(caps);
	cap_free(caps);
}

#endif
