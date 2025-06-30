/* Copyright (c) 2025 Patrick Cernko, see the included COPYING file
 */

#include "lib.h"
#include "module-dir.h"

#include "doveadm-replicator-plugin.h"
#include "doveadm-replicator.h"


const char *doveadm_replicator_plugin_version = DOVECOT_ABI_VERSION;

void doveadm_replicator_plugin_init(struct module *module ATTR_UNUSED)
{
        doveadm_register_replicator_commands();
}

void doveadm_replicator_plugin_deinit(void)
{
	/* the hooks array is freed already */
}
