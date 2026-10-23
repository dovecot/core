#!/usr/bin/env python3

"""Generate all-settings.c from the settings-related structs in the given
source files.

Usage: settings-get.py <files> [-- <linked files>]

The config process and doveconf need to know about all the settings, including
the ones used only by other binaries and by the plugins. Instead of linking
all of that code into them, this script copies the settings-related parts of
the source files into a single all-settings.c:

 - the settings structs (struct *_settings { ... })
 - the setting_define arrays and the DEF() etc. macros that they use
 - the default settings and the setting_parser_infos
 - the service settings and their default settings
 - the code inside "/* <settings checks> */" .. "/* </settings checks> */"

The <files> list should have the headers first, so the types are defined
before they're used by the .c files.

The <linked files> are already linked into the config binaries via
libdovecot.so, so their contents aren't copied. Only extern declarations are
written for their setting_parser_infos.

Finally the arrays listing all the found infos and services are written:

 - all_default_infos[]: all setting_parser_infos
 - config_default_services[]: all service_settings and their defaults

The source files are parsed line by line with simple regexps, so they must
follow the usual coding style. For example, a block that is copied ends at
the first line containing "};"."""

import re
import sys

# Written to the beginning of all-settings.c. CONFIG_BINARY allows the copied
# code to leave out parts that are needed only by the real binaries.
# PLUGIN_BUILD includes the settings of the LDAP and Lua code, which can be
# built either as plugins or into the binaries (BUILTIN_LDAP, BUILTIN_LUA).
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

# Settings-related structures, which are copied until the end of the block.
# These match both type definitions (in headers) and variable definitions.
SETTINGS_BLOCK_RES = [
    re.compile(r"struct .*_settings \{"),
    re.compile(r"struct setting_define.*\{"),
    re.compile(r"const char \*const .*_never_inherited_by\[\] = \{"),
    re.compile(r"struct .*_default_settings = \{"),
    re.compile(r"struct setting_keyvalue.*_default_settings_keyvalue\[\] = \{"),
]
# struct service_settings <name>_service_settings = {
SERVICE_SETTINGS_RE = re.compile(r"^struct service_settings (.*) = \{")
# Default settings for a service: <name>_service_settings_defaults[]
SERVICE_DEFAULTS_RE = re.compile(
    r"^const struct setting_keyvalue (.*_defaults)\[\] = \{"
)
# The setting_parser_infos are added to all_default_infos[]
PARSER_INFO_RE = re.compile(r"^const struct setting_parser_info (.*) = \{")
# Macros used for the setting_define arrays. These are copied as single lines,
# or until the end of a multi-line macro.
DEF_MACRO_RES = [
    re.compile(r"#define.*DEF"),
    re.compile(r"^#undef.*DEF"),
    re.compile(r"ARRAY_DEFINE_TYPE.*_settings"),
]
# Code between these markers is copied as-is. It contains code needed by the
# setting_parser_infos, e.g. check_func() implementations.
CHECKS_BEGIN = "/* <settings checks> */"
CHECKS_END = "/* </settings checks> */"
# Preprocessor conditionals: directive and its argument
CONDITIONAL_RE = re.compile(r"^#\s*(ifdef|ifndef|if|elif|else|endif)\b\s*(.*?)\s*$")
DEFINE_RE = re.compile(r"^#\s*define\s+(\w+)\b")
STATIC_RE = re.compile(r"^\s*static\b")
# Variable name (optionally array) followed by "= {"
WEAK_RE = re.compile(r"(\w+(?:\[\])?)(\s*=\s*\{)")
SERVICE_NAME_RE = re.compile(r"^(.*)_service_settings$")


def add_weak(line):
    """Add __attribute__((weak)) to a non-static variable definition.

    The variables copied to all-settings.c are also defined in the plugins,
    which doveconf and config dlopen() at runtime. ASAN reports such
    duplicate definitions as ODR violations, but not when one of them is
    weak. The plugin's strong definition then takes precedence at runtime.

    Static variables are skipped, because clang rejects the weak attribute
    for them (and they can't conflict anyway)."""
    if STATIC_RE.search(line):
        return line
    return WEAK_RE.sub(r"\1 __attribute__((weak))\2", line, count=1)


def ifdefs_begin(ifdefs):
    """Return lines that open the given #if conditions."""
    return "".join(ifdef + "\n" for ifdef in ifdefs)


def ifdefs_wrap(ifdefs, text):
    """Wrap text inside the given #if conditions."""
    return ifdefs_begin(ifdefs) + text + "#endif\n" * len(ifdefs)


class Conditionals:
    """Track the currently open preprocessor conditionals. Each one is
    stored as the lines needed to reopen it, e.g. "#ifdef FOO\n#else"
    for the #else branch. Header guards are ignored.

    The copied parts are written to all-settings.c inside the same
    conditionals as they were in the original file. Only the conditionals
    are copied, not the rest of the code between them, so they need to be
    reopened for each copied part."""

    def __init__(self):
        self.stack = []
        # #ifndef name, if the previous line was "#ifndef name"
        self.ifndef_name = None

    def update(self, line):
        """Update the conditionals stack with the given line."""
        ifndef_name, self.ifndef_name = self.ifndef_name, None
        m = DEFINE_RE.search(line)
        if m is not None and m.group(1) == ifndef_name:
            # header guard - forget about it
            self.stack[-1] = None
            return

        m = CONDITIONAL_RE.search(line)
        if m is None:
            return
        directive, arg = m.group(1), m.group(2)
        if directive in ("ifdef", "ifndef", "if"):
            self.stack.append(line.rstrip("\n"))
            if directive == "ifndef":
                self.ifndef_name = arg
        elif len(self.stack) == 0:
            # Unbalanced #endif etc. - ignore
            pass
        elif directive == "endif":
            self.stack.pop()
        elif self.stack[-1] is not None:
            # #else or #elif
            self.stack[-1] += "\n" + line.rstrip("\n")

    def get(self):
        """Return the currently open conditionals, outermost first."""
        return [cond for cond in self.stack if cond is not None]


class SettingsFile:
    """Settings parsed from a single source file.

    The file is parsed with a state machine: each parse_*() method handles
    a single line and returns the method for parsing the next line."""

    def __init__(self, path):
        self.path = path
        # Settings structs and macros to copy
        self.contents = ""
        # Code copied from inside <settings checks>
        self.code = ""
        # extern declarations for the setting_parser_infos
        self.externs = ""
        # setting_parser_info name => &name, entry for all_default_infos[]
        self.infos = {}
        # struct service_settings names
        self.services = []
        # names of the setting_keyvalue *_defaults[] arrays
        self.service_defaults = set()

        # Currently open #if conditions
        self.conditionals = Conditionals()
        # Conditions that were open when the current block began
        self.ifdefs = []
        # Number of #if conditions written to contents/code, which still
        # need to be closed with #endif.
        self.ifdefs_open = 0

    def parse(self):
        state = self.parse_root
        with open(self.path, encoding="utf-8", errors="surrogateescape") as f:
            for line in f:
                state = state(line)

    def write_contents(self, line, block_ends):
        """Copy a line of a block to contents. The block is wrapped inside
        the conditionals that were open when it began: they are written
        before its first line and closed after its last line."""
        if len(self.ifdefs) > 0 and self.ifdefs_open == 0:
            self.contents += ifdefs_begin(self.ifdefs)
            self.ifdefs_open = len(self.ifdefs)
        self.contents += line
        if block_ends and self.ifdefs_open > 0:
            self.contents += "#endif\n" * self.ifdefs_open
            self.ifdefs_open = 0

    def parse_root(self, line):
        """Parse a line outside any copied block. Track the conditionals
        and look for the beginning of something to copy."""
        # The conditionals are tracked only here, so any conditionals
        # inside a copied block are copied as-is.
        self.conditionals.update(line)
        self.ifdefs = self.conditionals.get()

        state = self.parse_root
        # Python 3.6 compatible: no assignment expressions
        service_m = SERVICE_SETTINGS_RE.search(line)
        defaults_m = SERVICE_DEFAULTS_RE.search(line)
        info_m = PARSER_INFO_RE.search(line)
        if any(r.search(line) for r in SETTINGS_BLOCK_RES):
            # Only variables can be weak, not type definitions
            if "= {" in line:
                line = add_weak(line)
            state = self.parse_block
        elif service_m is not None:
            line = add_weak(line)
            self.services.append(service_m.group(1))
            state = self.parse_block
        elif defaults_m is not None:
            line = add_weak(line)
            self.service_defaults.add(defaults_m.group(1))
            state = self.parse_block
        elif info_m is not None:
            name = info_m.group(1)
            self.infos[name] = ifdefs_wrap(self.ifdefs, "\t&%s,\n" % name)
            # Add forward declaration for the info struct. This may be
            # needed by the ext_check() functions.
            self.externs += "extern const struct setting_parser_info %s;\n" % name
            line = add_weak(line)
            state = self.parse_block
        elif CHECKS_BEGIN in line:
            # The code may contain #ifs of its own, so the whole region is
            # wrapped inside the conditionals instead of each block.
            self.code += ifdefs_begin(self.ifdefs) + line
            self.ifdefs_open = len(self.ifdefs)
            return self.parse_checks

        if state == self.parse_block:
            # Copy the block's first line (and maybe also the last).
            return self.parse_block(line)

        if any(r.search(line) for r in DEF_MACRO_RES):
            if line.endswith("\\\n"):
                # multi-line macro
                self.write_contents(line, False)
                return self.parse_macro
            self.write_contents(line, True)
        return self.parse_root

    def parse_block(self, line):
        """Copy until the end of the block."""
        if "};" in line:
            self.write_contents(line, True)
            return self.parse_root
        self.write_contents(line, False)
        return self.parse_block

    def parse_macro(self, line):
        """Copy until the macro doesn't continue to the next line."""
        if line.endswith("\\\n"):
            self.write_contents(line, False)
            return self.parse_macro
        self.write_contents(line, True)
        return self.parse_root

    def parse_checks(self, line):
        """Copy everything until the end of <settings checks>."""
        if re.search(r"^const .*= \{", line):
            line = add_weak(line)
        self.code += line
        if CHECKS_END in line:
            self.code += "#endif\n" * self.ifdefs_open
            self.ifdefs_open = 0
            return self.parse_root
        return self.parse_checks


def service_name(name):
    """Return service name from <name>_service_settings."""
    m = SERVICE_NAME_RE.search(name)
    if m is None:
        sys.exit("unexpected service name %s" % name)
    return m.group(1)


def main():
    out = sys.stdout
    out.write(HEADER)

    services = []
    service_defaults = set()
    infos = {}

    # Files after "--" are linked files.
    linked_file = False
    for path in sys.argv[1:]:
        if path == "--":
            linked_file = True
            continue

        f = SettingsFile(path)
        f.parse()
        services += f.services
        service_defaults |= f.service_defaults
        infos.update(f.infos)

        # Write each file's parts in the same order as the files are given,
        # so that the headers' type definitions come first.
        out.write("/* %s */\n" % path)
        out.write(f.externs)
        if not linked_file:
            out.write(f.code)
            out.write(f.contents)

    # Write an array of default services and their default settings,
    # sorted by the service name.
    out.write("static const struct config_service config_default_services[] = {\n")
    for service in sorted(services, key=service_name):
        defaults = service + "_defaults"
        if defaults not in service_defaults:
            defaults = "NULL"
        out.write("\t{ &%s, %s },\n" % (service, defaults))
    out.write("\t{ NULL, NULL }\n")
    out.write("};\n")

    # Write a list of all settings infos, sorted by the variable name.
    out.write("const struct setting_parser_info *all_default_infos[] = {\n")
    for name in sorted(infos):
        out.write(infos[name])
    out.write("\tNULL\n")
    out.write("};\n")
    out.write(
        "const struct setting_parser_info *const *all_infos = all_default_infos;\n"
    )
    out.write(
        "const struct config_service *config_all_services = config_default_services;\n"
    )


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="surrogateescape")
    main()
