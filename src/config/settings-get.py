#!/usr/bin/env python3

"""Generate all-settings.c from the settings-related structs in the given
source files."""

import re
import sys

HEADER = """\
/* WARNING: THIS FILE IS GENERATED - DO NOT PATCH!
   It's not enough alone in any case, because the defaults may be
   coming from the individual *-settings.c in some situations. If you
   wish to modify defaults, change the other *-settings.c files and
   just delete this file. This file will be automatically regenerated
   by make. (This file is distributed in the tarball only because some
   systems might not have Python installed.) */
#include "lib.h"
#include "array.h"
#include "str.h"
#include "ipwd.h"
#include "var-expand.h"
#include "oauth2.h"
#include "file-lock.h"
#include "fsync-mode.h"
#include "hash-format.h"
#include "net.h"
#include "unichar.h"
#include "uri-util.h"
#include "settings-parser-http-url.h"
#include "hash-method.h"
#include "guid.h"
#include "settings.h"
#include "master-interface.h"
#include "message-header-parser.h"
#include "imap-urlauth-worker-common.h"
#include "mailbox-list.h"
#include "doc.h"
#include "all-settings.h"
#include <unistd.h>
#define CONFIG_BINARY
#define PLUGIN_BUILD
"""

WEAK_RE = re.compile(r"(\w+(?:\[\])?)(\s*=\s*\{)")


def add_weak(line):
    return WEAK_RE.sub(r"\1 __attribute__((weak))\2", line, count=1)


def is_static(line):
    return re.search(r"^\s*static\b", line) is not None


def service_name(name):
    m = re.search(r"^(.*)_service_settings$", name)
    if m is None:
        sys.exit("unexpected service name %s" % name)
    return m.group(1)


def main():
    out = sys.stdout
    out.write(HEADER)

    services = []
    service_defaults = {}
    infos = {}

    linked_file = False
    for path in sys.argv[1:]:
        if path == "--":
            linked_file = True
            continue

        state = "root"
        file_contents = ""
        externs = ""
        code = ""
        ifdefs = []
        ifdefs_open = 0

        with open(path, encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                write = False
                if state == "root":
                    m = (re.search(r"(^#ifdef .*)$", line) or
                         re.search(r"^(#if .*)$", line))
                    if m is not None:
                        ifdefs.append(m.group(1))
                    elif re.search(r"^#endif", line):
                        if ifdefs:
                            ifdefs.pop()

                    if (re.search(r"struct .*_settings \{", line) or
                            re.search(r"struct setting_define.*\{", line) or
                            re.search(r"const char \*const .*_never_inherited_by\[\] = \{", line) or
                            re.search(r"struct .*_default_settings = \{", line) or
                            re.search(r"struct setting_keyvalue.*_default_settings_keyvalue\[\] = \{", line)):
                        # settings-related structure - copy.
                        # For variable definitions (containing = {), add
                        # __attribute__((weak)) so ASAN doesn't report ODR
                        # violations when the same symbol is also present
                        # in a dlopen()'d plugin .so.
                        if "= {" in line and not is_static(line):
                            line = add_weak(line)
                        state = "copy-to-end-of-block"
                    elif (m := re.search(r"^struct service_settings (.*) = \{", line)):
                        # service settings - copy and add to list of
                        # services.
                        if not is_static(line):
                            line = add_weak(line)
                        state = "copy-to-end-of-block"
                        services.append(m.group(1))
                    elif (m := re.search(r"^const struct setting_keyvalue (.*_defaults)\[\] = \{", line)):
                        # service's default settings as keyvalues - copy
                        # and add to list of defaults.
                        service_defaults[m.group(1)] = True
                        if not is_static(line):
                            line = add_weak(line)
                        state = "copy-to-end-of-block"
                    elif (m := re.search(r"^const struct setting_parser_info (.*) = \{", line)):
                        # info structure for settings
                        cur_name = m.group(1)
                        infos[cur_name] = ("\n".join(ifdefs) +
                                           "\n\t&%s,\n" % cur_name +
                                           "#endif\n" * len(ifdefs))
                        # Add forward declaration for the info struct.
                        # This may be needed by the ext_check() functions.
                        externs += "extern const struct setting_parser_info %s;\n" % cur_name
                        if not is_static(line):
                            line = add_weak(line)
                        state = "copy-to-end-of-block"
                    elif re.search(r"/\* <settings checks> \*/", line):
                        # Anything inside <settings check> ...
                        # </settings check> is copied.
                        state = "copy-to-end-of-settings-checks"
                        code += "\n".join(ifdefs) + "\n"
                        ifdefs_open = len(ifdefs)
                        code += line

                    if (re.search(r"#define.*DEF", line) or
                            re.search(r"^#undef.*DEF", line) or
                            re.search(r"ARRAY_DEFINE_TYPE.*_settings", line)):
                        # macro for setting_define { ... } - copy.
                        write = True
                        if re.search(r"\\$", line):
                            # multi-line macro
                            state = "copy-to-end-of-macro"
                elif state == "copy-to-end-of-macro":
                    # Continue copying macro until the line doesn't end
                    # with '\'
                    write = True
                    if not re.search(r"\\$", line):
                        state = "root"
                elif state == "copy-to-end-of-settings-checks":
                    if re.search(r"^const .*= \{", line):
                        line = add_weak(line)
                    code += line
                    if re.search(r"/\* </settings checks> \*/", line):
                        state = "root"
                        code += "#endif\n" * ifdefs_open
                        ifdefs_open = 0

                if state == "copy-to-end-of-block":
                    write = True
                    if "};" in line:
                        state = "root"

                if write:
                    if len(ifdefs) > 0 and ifdefs_open == 0:
                        file_contents += "\n".join(ifdefs) + "\n"
                        ifdefs_open = len(ifdefs)
                    file_contents += line
                    if state == "root" and ifdefs_open > 0:
                        file_contents += "#endif\n" * ifdefs_open
                        ifdefs_open = 0

        out.write("/* %s */\n" % path)
        out.write(externs)
        if linked_file:
            # The code and contents are already linked via libdovecot.so.
            # Don't add them again.
            pass
        else:
            out.write(code)
            out.write(file_contents)

    # Write an array of default services and their default settings.
    out.write("static const struct config_service config_default_services[] = {\n")
    services.sort(key=service_name)
    for service in services:
        defaults = "NULL"
        if service + "_defaults" in service_defaults:
            defaults = service + "_defaults"
        out.write("\t{ &%s, %s },\n" % (service, defaults))
    out.write("\t{ NULL, NULL }\n")
    out.write("};\n")

    # Write a list of all settings infos.
    out.write("const struct setting_parser_info *all_default_infos[] = {\n")
    for name in sorted(infos):
        out.write(infos[name])
    out.write("\tNULL\n")
    out.write("};\n")
    out.write("const struct setting_parser_info *const *all_infos = all_default_infos;\n")
    out.write("const struct config_service *config_all_services = config_default_services;\n")


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="surrogateescape")
    main()
