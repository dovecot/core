#!/usr/bin/env python3

"""Generate history structs for renamed settings and changed default values."""

import argparse
import sys
from pathlib import Path

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


class SettingDefault:
    """Handle the logic behind a setting's changed default value."""

    def __init__(self, key: str, old_value: str, version_text: str, version: [int]):
        """Initialize a setting's default value change object."""
        self.key = key
        self.old_value = old_value
        self.version_text = version_text
        self.version = version

    def render(self) -> str:
        """Render this setting's default value update to text."""
        return STRUCT_TEMPLATE % (self.key, self.old_value, self.version_text)


class SettingRename:
    """Handle the logic behind a setting's changed name."""

    def __init__(self, old_key: str, new_key: str, version_text: str, version: [int]):
        """Initialize a setting's default value change object."""
        self.old_key = old_key
        self.new_key = new_key
        self.version_text = version_text
        self.version = version

    def render(self) -> str:
        """Render this setting's rename to text."""
        return STRUCT_TEMPLATE % (self.old_key, self.new_key, self.version_text)


def die(message: str):
    """Die with a message."""
    module_filename = Path(__file__).name
    print(f"{module_filename}: {message}", file=sys.stderr)
    sys.exit(1)


def parse_version(version: str) -> [int]:
    """Parse a string version into a list of integers."""
    values = version.split(".")
    parsed = []
    for value in values:
        try:
            parsed.append(int(value))
        except ValueError as e:
            raise ValueError("Invalid version {version}: {e}") from e
    return parsed


def render_version(version: [int]) -> str:
    """Produce a textual render of the a version."""
    return ".".join([str(v) for v in version])


def process_version(ce_version: str, pro_version: str, pro: bool) -> (str, [int]):
    """Parse and validate version information."""
    version_text = pro_version if pro else ce_version
    version = parse_version(version_text) if version_text not in ("", "-") else None
    return (version_text, version)


def check_version(prev_version: [int], cur_version: [int]):
    """Fail if version ordering is incorrect."""
    if prev_version is not None and cur_version > prev_version:
        cur_version_text = render_version(cur_version)
        prev_version_text = render_version(prev_version)
        raise ValueError(
            "Invalid version sort order "
            f"between {cur_version_text} and {prev_version_text}: "
            "Please fix the input file"
        )
    return cur_version


def process(input_file: str, contents: str, pro: bool) -> (str, str):
    """Produce the renames and defaults structs from the input data."""
    renames = ""
    defaults = ""
    renames_prev_version = None
    defaults_prev_version = None
    for line, data in enumerate(contents.splitlines()):
        line = line + 1
        values = data.split("\t")

        if len(values) != 5:
            die(
                f"{input_file}:{line}: "
                f"Invalid contents `{data}`: "
                "Expecting 5 fields"
            )

        try:
            (version_text, version) = process_version(
                ce_version=values[3], pro_version=values[4], pro=pro
            )
        except ValueError as e:
            die(f"{input_file}:{line}: {e}")

        if version is None:
            continue

        if values[0] == "rename":
            try:
                renames_prev_version = check_version(renames_prev_version, version)
            except ValueError as e:
                die(f"{input_file}:{line}: {e}")

            rename = SettingRename(
                old_key=values[1],
                new_key=values[2],
                version_text=version_text,
                version=version,
            )
            renames += rename.render()
        elif values[0] == "default":
            try:
                defaults_prev_version = check_version(defaults_prev_version, version)
            except ValueError as e:
                die(f"{input_file}:{line}: {e}")

            default = SettingDefault(
                key=values[1],
                old_value=values[2],
                version_text=version_text,
                version=version,
            )
            defaults += default.render()
        else:
            die(f"{input_file}:{line}: Unrecognized marker in `{data}`")
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

    input_file = getattr(args, "input-file")
    output_file = getattr(args, "output-file")

    with open(input_file, mode="r", encoding="utf-8") as f_in:
        contents = f_in.read()
        (renames, defaults) = process(input_file, contents, pro=bool(args.pro))

        with open(output_file, mode="w", encoding="utf-8") as f_out:
            f_out.write(FILE_TEMPLATE % (renames, defaults))


if __name__ == "__main__":
    main()
