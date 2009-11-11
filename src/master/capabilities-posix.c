#include "common.h"
#include "capabilities.h"

#ifdef HAVE_LIBCAP

#include <sys/capability.h>

void drop_capabilities(void)
{
	/* the capabilities that we *need* in order to operate */
	static cap_value_t suidcaps[] = {
		CAP_CHOWN,
		CAP_KILL,
		CAP_SYS_CHROOT,
		CAP_SETUID,
		CAP_SETGID,
		CAP_NET_BIND_SERVICE,
		/* we may want to open any config/log files */
		CAP_DAC_OVERRIDE
	};
	cap_t caps;

	caps = cap_init();
	cap_clear(caps);
	cap_set_flag(caps, CAP_PERMITTED,
		     N_ELEMENTS(suidcaps), suidcaps, CAP_SET);
	cap_set_flag(caps, CAP_EFFECTIVE,
		     N_ELEMENTS(suidcaps), suidcaps, CAP_SET);
	cap_set_proc(caps);
	cap_free(caps);
}

#endif
