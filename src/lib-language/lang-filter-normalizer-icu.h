#ifndef LANG_FILTER_NORMALIZER_ICU_H
#define LANG_FILTER_NORMALIZER_ICU_H

struct module;

#define LANG_FILTER_NORMALIZER_ICU_MODULE_NAME "lang_filter_normalizer_icu"

/* The normalizer-icu filter class implemented with libicu. The
   lang_filter_normalizer_icu module registers it when the module is
   initialized. The module can be loaded via mail_plugins, or it's loaded
   when it's first needed. */
extern const struct lang_filter lang_filter_normalizer_icu_class;

void lang_filter_normalizer_icu_init(struct module *module);
void lang_filter_normalizer_icu_deinit(void);

#endif
