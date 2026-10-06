#!/usr/bin/env python3

"""Verify struct setting_plugin_info declarations in all-settings.c:

 - The plugin exists in some Makefile.am
 - The required plugins exist, and they are loaded before the plugin, i.e.
   their filenames sort before the plugin's filename.

Usage: plugin-infos-check.py all-settings.c Makefile.am [Makefile.am...]"""

import re
import sys

PLUGIN_INFO_RE = re.compile(
    r"struct setting_plugin_info \w+[^=]*= \{(.*?)\n\};", re.S)
PLUGIN_RE = re.compile(r'\.plugin = "([^"]+)"')
REQUIRED_RE = re.compile(
    r"\.required_plugins = \(const char \*const \[\]\) \{(.*?)\}", re.S)
LA_FILE_RE = re.compile(r"\b(lib\w+)\.la\b")


def plugin_name(fname):
    """lib<nn>_<name>_plugin -> <name>"""
    name = re.sub(r"^lib(\d+_)?", "", fname)
    return re.sub(r"_plugin$", "", name)


def load_order_key(fname):
    """Plugins are loaded in the order of their filenames without the
    "lib" prefix."""
    return fname[3:] if fname.startswith("lib") else fname


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    all_settings = sys.argv[1]

    la_files = set()
    for makefile in sys.argv[2:]:
        with open(makefile, encoding="utf-8") as f:
            la_files.update(LA_FILE_RE.findall(f.read()))
    plugin_fnames = {}
    for fname in la_files:
        plugin_fnames.setdefault(plugin_name(fname), fname)

    with open(all_settings, encoding="utf-8",
              errors="surrogateescape") as f:
        contents = f.read()

    errors = []
    count = 0
    for block in PLUGIN_INFO_RE.findall(contents):
        m = PLUGIN_RE.search(block)
        if m is None:
            errors.append("setting_plugin_info without .plugin: %s" % block)
            continue
        plugin = m.group(1)
        count += 1
        if plugin not in la_files:
            errors.append("Plugin %s not found from any Makefile.am" %
                          plugin)

        m = REQUIRED_RE.search(block)
        if m is None:
            continue
        for required in re.findall(r'"([^"]+)"', m.group(1)):
            required_fname = plugin_fnames.get(required)
            if required_fname is None:
                errors.append("Plugin %s requires plugin %s, which isn't "
                              "found from any Makefile.am" %
                              (plugin, required))
            elif load_order_key(required_fname) >= load_order_key(plugin):
                errors.append("Plugin %s requires plugin %s, but %s is "
                              "loaded after %s" %
                              (plugin, required, required_fname, plugin))
    if count == 0:
        errors.append("No setting_plugin_infos found from %s" % all_settings)

    for error in errors:
        print(error, file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
