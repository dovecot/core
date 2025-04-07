#!/usr/bin/env python

"""Generate history structs for renamed settings and changed default values."""

import argparse
import sys

FILE_TEMPLATE = """\
static const struct setting_history_rename settings_history_core_renames[] = {
%s\
};
static const struct setting_history_default settings_history_core_defaults[] = {
%s\
};
"""

STRUCT_TEMPLATE = """\
  { "%s", "%s", "%s" },
"""


def die(message: str):
    """Die with a message."""
    print(message, file=sys.stderr)
    sys.exit(1)


def parse_version(line: int, version: str) -> [int]:
    """Parse a string version into a list of integers."""
    values = version.split(".")
    parsed = []
    for value in values:
        try:
            int_value = int(value)
            parsed.append(int_value)
        except ValueError as e:
            die(f"Line {line}: Invalid version {version}: {e}")
    return parsed


def check_version(line: int, prev_version: [int], cur_version: [int]):
    """Fail if version ordering is incorrect."""
    if prev_version is not None and cur_version > prev_version:
        die(f"Line {line}: Invalid version sort order")
    return cur_version


def process(contents: str, pro: bool) -> (str, str):
    """Produce the renames and defaults structs from the input data."""
    renames = ""
    defaults = ""
    renames_prev_version = None
    defaults_prev_version = None
    for line, data in enumerate(contents.splitlines()):
        line = line + 1
        values = data.split("\t")

        if len(values) != 5:
            die(f"Line {line}: Invalid contents `{data}`: Expecting 5 fields")

        ce_version = values[3]
        pro_version = values[4]
        version_text = pro_version if pro else ce_version

        if version_text == "":
            continue

        version = parse_version(line, version_text)

        if values[0] == "rename":
            old_key = values[1]
            new_key = values[2]
            renames += STRUCT_TEMPLATE % (old_key, new_key, version_text)
            renames_prev_version = check_version(line, renames_prev_version, version)
        elif values[0] == "default":
            key = values[1]
            old_value = values[2]
            defaults += STRUCT_TEMPLATE % (key, old_value, version_text)
            defaults_prev_version = check_version(line, defaults_prev_version, version)
        else:
            die(f"Line {line}: Unrecognized marker in `{data}`")
    return (renames, defaults)


def main():
    """Entry point."""
    parser = argparse.ArgumentParser(
        prog="settings-history.py",
        description="Generate header file for settings migration data",
    )
    parser.add_argument(
        "input-file",
        type=str,
        help="Input data file e.g. settings-history-core.txt",
    )
    parser.add_argument(
        "output-file",
        type=str,
        help="Output header file e.g. settings-history-core.h",
    )
    parser.add_argument(
        "--pro",
        type=int,
        choices=[0, 1],
        help="Whether to generate settings migration data for Pro",
    )
    args = parser.parse_args()

    with open(getattr(args, "input-file"), mode="r", encoding="utf-8") as f_in:
        contents = f_in.read()
        (renames, defaults) = process(contents, pro=bool(args.pro))

        with open(getattr(args, "output-file"), mode="w", encoding="utf-8") as f_out:
            f_out.write(FILE_TEMPLATE % (renames, defaults))


if __name__ == "__main__":
    main()
