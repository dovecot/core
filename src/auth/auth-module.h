#ifndef __AUTH_MODULE_H
#define __AUTH_MODULE_H

struct auth_module *auth_module_open(const char *name);
void auth_module_close(struct auth_module *module);

void *auth_module_sym(struct auth_module *module, const char *name);

#endif
