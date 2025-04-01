#!/usr/bin/env python3
# Copyright (c) 2025 Dovecot authors, see the included COPYING file

import argparse
import bisect
import copy
import re
import sys
from pathlib import Path


source_files = []

ud_codepoints = []
ud_codepoints_first = []
ud_codepoints_last = []
ud_codepoints_index = {}

ud_codepoints_index8 = {}
ud_codepoints_index16 = {}
ud_codepoints_index16_reused = {}
ud_codepoints_index16_offsets = {}
ud_codepoints_index24 = {}
ud_codepoints_index24_reused = {}
ud_codepoints_index24_offsets = {}
ud_codepoints_index32 = {}
ud_codepoints_index32_reused = {}
ud_codepoints_index32_offsets = {}
ud_codepoints_index16_blocks = 1
ud_codepoints_index24_blocks = 2
ud_codepoints_index32_blocks = 2

ud_decomposition_type_names = []
ud_decompositions = []
ud_decomposition_max_length = 0

ud_composition_pairs = {}
ud_composition_composites = {}
ud_composition_exclusions = {}
ud_compositions = []
ud_composition_primaries = []
ud_compositions_max_per_starter = 0

ud_case_mappings = []
ud_case_mapping_max_length = 0


class UCDFileOpen:
    def __init__(self, filename):
        self.filename = filename

    def __enter__(self):
        global ucd_dir
        global source_files

        self.fd = open(ucd_dir + "/" + self.filename, mode="r", encoding="utf-8")
        source_files.append(self.filename)
        return self

    def __exit__(self, exception_type, exception_value, exception_traceback):
        self.fd.close()

    def __str__(self):
        return self.filename


class CodePointData:
    def mergeFrom(self, data, default=False):
        for attr in dir(data):
            if callable(getattr(data, attr)):
                continue
            if attr.startswith("__"):
                continue
            if default and hasattr(self, attr):
                continue
            setattr(self, attr, getattr(data, attr))


class CodePointRange:
    def insert(self, n):
        global ud_codepoints
        global ud_codepoints_first
        global ud_codepoints_last

        ud_codepoints.insert(n, self)
        ud_codepoints_first.insert(n, self.cp_first)
        ud_codepoints_last.insert(n, self.cp_last)

    def modify(self, n):
        global ud_codepoints
        global ud_codepoints_first
        global ud_codepoints_last

        ud_codepoints_first[n] = self.cp_first
        ud_codepoints_last[n] = self.cp_last

    def __new__(cls, cp_first, cp_last, data, default=False):
        global ud_codepoints
        global ud_codepoints_first
        global ud_codepoints_last

        cprn_first = None

        if len(ud_codepoints) == 0:
            cprn = super().__new__(cls)
            cprn.cp_first = cp_first
            cprn.cp_last = cp_last
            cprn.data = data
            cprn.insert(0)
            return

        idx_first = bisect.bisect_left(ud_codepoints_first, cp_first)
        idx_last = bisect.bisect_right(ud_codepoints_last, cp_last)
        rng_first = idx_first - 1
        rng_last = idx_last + 1
        if rng_last >= len(ud_codepoints):
            rng_last = len(ud_codepoints) - 1

        # Check existing ranges
        nn = None
        n = rng_first
        while n <= rng_last:
            cpr = ud_codepoints[n]
            pos = n
            n += 1

            # No overlap with this range
            if cp_last < cpr.cp_first or cp_first > cpr.cp_last:
                continue
            # Exact match
            if cp_first == cpr.cp_first and cp_last == cpr.cp_last:
                cpr.data.mergeFrom(data, default)
                return cpr
            # New range fully envelops existing
            if cp_first <= cpr.cp_first and cp_last >= cpr.cp_last:
                # Split off range before
                if cp_first < cpr.cp_first:
                    cprn = super().__new__(cls)
                    cprn.cp_first = cp_first
                    cprn.cp_last = cpr.cp_first - 1
                    cprn.data = copy.deepcopy(data)
                    cprn.insert(pos)
                    rng_last += 1
                    if cprn_first is None:
                        cprn_first = cprn
                # Merge with existing
                cpr.data.mergeFrom(data, default)
                # Split off range after
                if cp_last > cpr.cp_last:
                    cp_first = cpr.cp_last + 1
                    nn = pos + 1
                    continue
                break
            # New range fully enveloped by existing
            if cp_first > cpr.cp_first and cp_last < cpr.cp_last:
                cprn = super().__new__(cls)
                cprn.cp_first = cp_last + 1
                cprn.cp_last = cpr.cp_last
                cprn.data = cpr.data
                cprn.insert(pos + 1)
                rng_last += 1
                cpr.cp_last = cp_first - 1
                cpr.modify(pos)
                cprn = super().__new__(cls)
                cprn.cp_first = cp_first
                cprn.cp_last = cp_last
                cprn.data = copy.deepcopy(cpr.data)
                cprn.data.mergeFrom(data, default)
                cprn.insert(pos + 1)
                rng_last += 1
                return cprn
            # New range aligns with beginning of existing
            if cp_first == cpr.cp_first and cp_last < cpr.cp_last:
                cpr.cp_first = cp_last + 1
                cpr.modify(pos)
                cprn = super().__new__(cls)
                cprn.cp_first = cp_first
                cprn.cp_last = cp_last
                cprn.data = copy.deepcopy(cpr.data)
                cprn.data.mergeFrom(data, default)
                cprn.insert(pos)
                rng_last += 1
                return cprn
            # New range aligns with end of existing
            if cp_first > cpr.cp_first and cp_last == cpr.cp_last:
                cpr.cp_last = cp_first - 1
                cpr.modify(pos)
                cprn = super().__new__(cls)
                cprn.cp_first = cp_first
                cprn.cp_last = cp_last
                cprn.data = copy.deepcopy(cpr.data)
                cprn.data.mergeFrom(data, default)
                cprn.insert(pos + 1)
                rng_last += 1
                return cprn
            # New range crosses the beginning of existing
            if cp_first < cpr.cp_first and cp_last >= cpr.cp_first:
                cprn = super().__new__(cls)
                cprn.cp_first = cp_first
                cprn.cp_last = cpr.cp_first - 1
                cprn.data = data
                cprn.insert(pos)
                rng_last += 1
                cprn = super().__new__(cls)
                cprn.cp_first = cpr.cp_first
                cprn.cp_last = cp_last
                cprn.data = copy.deepcopy(cpr.data)
                cprn.data.mergeFrom(data, default)
                cprn.insert(pos + 1)
                rng_last += 1
                cpr.cp_first = cp_last + 1
                cpr.modify(pos + 2)
                return cprn
            # New range crosses the end of existing
            if cp_first <= cpr.cp_last and cp_last > cpr.cp_last:
                cprn = super().__new__(cls)
                cprn.cp_first = cp_first
                cprn.cp_last = cpr.cp_last
                cprn.data = copy.deepcopy(cpr.data)
                cprn.data.mergeFrom(data, default)
                cprn.insert(pos)
                rng_last += 1
                if cprn_first is None:
                    cprn_first = cprn
                tmp = cp_first
                cp_first = cpr.cp_last + 1
                cpr.cp_last = tmp - 1
                cpr.modify(pos + 1)
                nn = pos + 1
                continue

        cprn = super().__new__(cls)
        cprn.cp_first = cp_first
        cprn.cp_last = cp_last
        cprn.data = data
        if nn is None:
            cprn.insert(idx_first)
        else:
            cprn.insert(nn)
        if cprn_first is None:
            cprn_first = cprn

        return cprn_first


def die(message):
    module_filename = Path(__file__).name
    print(f"{module_filename}: {message}", file=sys.stderr)
    sys.exit(1)


def parse_cp_range(column):
    rng_hex = column.strip()
    if len(rng_hex) == 0:
        return None
    rng = rng_hex.split("..")

    cp_hex = rng[0].strip()
    cp_first = int(cp_hex, 16)
    cp_last = cp_first

    if len(rng) > 1:
        cp_hex = rng[1].strip()
        cp_last = int(cp_hex, 16)

    return (cp_first, cp_last)


def read_ucd_files():
    global ud_decomposition_type_names
    global ud_composition_exclusions

    # PropertyValueAliases.txt
    with UCDFileOpen("PropertyValueAliases.txt") as ucd:
        line_num = 0
        for line in ucd.fd:
            line_num = line_num + 1
            data = line.split("#")
            line = data[0].strip()
            if len(line) == 0:
                continue

            cols = line.split(";")
            if len(cols) < 3:
                die(f"{ucd}:{line_num}: Missing columns")

            prop = cols[0].strip()
            if prop == "dt":
                lval = cols[2].strip()
                ud_decomposition_type_names.append(lval)

    # UnicodeData.txt
    with UCDFileOpen("UnicodeData.txt") as ucd:
        cp_range_first = None
        line_num = 0
        for line in ucd.fd:
            line_num = line_num + 1
            data = line.split("#")
            line = data[0].strip()
            if len(line) == 0:
                continue

            cols = line.split(";")
            if len(cols) < 15:
                die(f"{ucd}:{line_num}: Missing columns")

            # (0) Code point in hex

            cp_first = cp_last = int(cols[0].strip(), 16)

            # (1) Name

            cp_name = cols[1].strip()

            x = re.search("<([^>]*), (First|Last)>", cp_name)
            if x:
                if x.group(2) == "First":
                    cp_range_first = cp_first
                    continue
                if x.group(2) == "Last" and cp_range_first is not None:
                    cp_first = cp_range_first
                    cp_name = "<%s>" % x.group(1)
                    cp_range_first = None

            cpd = CodePointData()
            cpd.name = cp_name

            # (2) General_Category

            cpd.general_category = cols[2].strip()

            # (3) Canonical_Combining_Class

            ccc = cols[3].strip()
            if ccc != "":
                cpd.canonical_combining_class = int(ccc)

            # (5) Decomposition_Type, Decomposition_Mapping

            x = re.search("(<([^>]*)> )?(.+)", cols[5].strip())
            if x:
                if x.group(2) is not None:
                    cpd.decomposition_type = x.group(2)
                dcs_txt = x.group(3).split(" ")
                dcs = []
                for dc_txt in dcs_txt:
                    dcs.append(int(dc_txt.strip(), 16))
                cpd.decomposition_first = dcs

            # (12) Simple_Uppercase_Mapping

            code = cols[12].strip()
            if code != "":
                cpd.simple_uppercase_mapping = int(code, 16)

            # (13) Simple_Lowercase_Mapping

            code = cols[13].strip()
            if code != "":
                cpd.simple_lowercase_mapping = int(code, 16)

            # (14) Simple_Titlecase_Mapping

            code = cols[14].strip()
            if code != "":
                cpd.simple_titlecase_mapping = int(code, 16)

            # Add range
            CodePointRange(cp_first, cp_last, cpd)

    # CaseFolding.txt
    with UCDFileOpen("CaseFolding.txt") as ucd:
        line_num = 0
        for line in ucd.fd:
            line_num = line_num + 1
            data = line.split("#")
            line = data[0].strip()
            if len(line) == 0:
                continue

            cols = line.split(";")
            if len(cols) < 3:
                die(f"{ucd}:{line_num}: Missing columns")

            cp_hex = cols[0].strip()
            if len(cp_hex) == 0:
                continue
            cp = int(cp_hex, 16)

            status = cols[1].strip()
            mapping = cols[2].strip()

            if status != "C" and status != "F":
                continue

            codes_hex = mapping.split(" ")
            if len(codes_hex) > 0:
                first_code_hex = codes_hex[0].strip()
                first_code = int(first_code_hex, 16)
                if len(codes_hex) > 1 or first_code != cp:
                    codes = []
                    for code_hex in codes_hex:
                        codes.append(int(code_hex, 16))

                    cpd = CodePointData()
                    cpd.case_folding = codes
                    CodePointRange(cp, cp, cpd)

    # CompositionExclusions.txt
    with UCDFileOpen("CompositionExclusions.txt") as ucd:
        for line in ucd.fd:
            data = line.split("#")

            cprng = parse_cp_range(data[0])
            if cprng is None:
                continue

            for cp in range(cprng[0], cprng[1] + 1):
                ud_composition_exclusions[cp] = True

    # DerivedNormalizationProps.txt
    with UCDFileOpen("DerivedNormalizationProps.txt") as ucd:
        line_num = 0
        for line in ucd.fd:
            line_num = line_num + 1
            data = line.split("#")
            line = data[0].strip()
            if len(line) == 0:
                continue

            cols = line.split(";")
            if len(cols) < 3:
                if len(cols) < 2:
                    die(f"{ucd}:{line_num}: Missing columns")
                continue

            cprng = parse_cp_range(cols[0])
            if cprng is None:
                continue

            prop = cols[1].strip()
            value = cols[2].strip()
            if prop == "NFD_QC":
                cpd = CodePointData()
                cpd.nfd_quick_check = value
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "NFKD_QC":
                cpd = CodePointData()
                cpd.nfkd_quick_check = value
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "NFC_QC":
                cpd = CodePointData()
                cpd.nfc_quick_check = value
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "NFKC_QC":
                cpd = CodePointData()
                cpd.nfkc_quick_check = value
                CodePointRange(cprng[0], cprng[1], cpd)

    # PropList.txt
    with UCDFileOpen("PropList.txt") as ucd:
        line_num = 0
        for line in ucd.fd:
            line_num = line_num + 1
            data = line.split("#")
            line = data[0].strip()
            if len(line) == 0:
                continue

            cols = line.split(";")
            if len(cols) < 2:
                die(f"{ucd}:{line_num}: Missing columns")

            cprng = parse_cp_range(cols[0])
            if cprng is None:
                continue

            prop = cols[1].strip()
            if prop == "White_Space":
                cpd = CodePointData()
                cpd.pb_g_white_space = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Pattern_White_Space":
                cpd = CodePointData()
                cpd.pb_i_pattern_white_space = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Quotation_Mark":
                cpd = CodePointData()
                cpd.pb_m_quotation_mark = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Dash":
                cpd = CodePointData()
                cpd.pb_m_dash = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Sentence_Terminal":
                cpd = CodePointData()
                cpd.pb_m_sentence_terminal = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Terminal_Punctuation":
                cpd = CodePointData()
                cpd.pb_m_terminal_punctuation = True
                CodePointRange(cprng[0], cprng[1], cpd)

    # SpecialCasing.txt
    with UCDFileOpen("SpecialCasing.txt") as ucd:
        line_num = 0
        for line in ucd.fd:
            line_num = line_num + 1
            data = line.split("#")
            line = data[0].strip()
            if len(line) == 0:
                continue

            # <code>; <lower>; <title>; <upper>; (<condition_list>;)? # <comment>
            cols = line.split(";")
            if len(cols) < 4:
                die(f"{ucd}:{line_num}: Missing columns")
            if len(cols) > 4 and len(cols[4].strip()) > 0:
                # Skip lines with condition list
                continue

            cp_hex = cols[0].strip()
            if len(cp_hex) == 0:
                continue
            cp = int(cp_hex, 16)

            lower = cols[1].strip()
            upper = cols[3].strip()

            cpd = None

            # Lowercase_Mapping
            codes_hex = lower.split(" ")
            if len(codes_hex) > 0:
                first_code_hex = codes_hex[0].strip()
                first_code = int(first_code_hex, 16)
                if len(codes_hex) > 1 or first_code != cp:
                    codes = []
                    for code_hex in codes_hex:
                        codes.append(int(code_hex, 16))

                    if cpd is None:
                        cpd = CodePointData()
                    cpd.lowercase_mapping = codes

            # Uppercase_Mapping
            codes_hex = upper.split(" ")
            if len(codes_hex) > 0:
                first_code_hex = codes_hex[0].strip()
                first_code = int(first_code_hex, 16)
                if len(codes_hex) > 1 or first_code != cp:
                    codes = []
                    for code_hex in codes_hex:
                        codes.append(int(code_hex, 16))

                    if cpd is None:
                        cpd = CodePointData()
                    cpd.uppercase_mapping = codes

            if cpd is not None:
                CodePointRange(cp, cp, cpd)

    # WordBreakProperty.txt
    with UCDFileOpen("WordBreakProperty.txt") as ucd:
        line_num = 0
        for line in ucd.fd:
            line_num = line_num + 1
            data = line.split("#")
            line = data[0].strip()
            if len(line) == 0:
                continue

            cols = line.split(";")
            if len(cols) < 2:
                die(f"{ucd}:{line_num}: Missing columns")

            cprng = parse_cp_range(cols[0])
            if cprng is None:
                continue

            prop = cols[1].strip()
            if prop == "CR":
                cpd = CodePointData()
                cpd.pb_wb_cr = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "LF":
                cpd = CodePointData()
                cpd.pb_wb_lf = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Newline":
                cpd = CodePointData()
                cpd.pb_wb_newline = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Extend":
                cpd = CodePointData()
                cpd.pb_wb_extend = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "ZWJ":
                cpd = CodePointData()
                cpd.pb_wb_zwj = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Regional_Indicator":
                cpd = CodePointData()
                cpd.pb_wb_regional_indicator = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Format":
                cpd = CodePointData()
                cpd.pb_wb_format = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Katakana":
                cpd = CodePointData()
                cpd.pb_wb_katakana = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Hebrew_Letter":
                cpd = CodePointData()
                cpd.pb_wb_hebrew_letter = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "ALetter":
                cpd = CodePointData()
                cpd.pb_wb_aletter = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Single_Quote":
                cpd = CodePointData()
                cpd.pb_wb_single_quote = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Double_Quote":
                cpd = CodePointData()
                cpd.pb_wb_double_quote = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "MidNumLet":
                cpd = CodePointData()
                cpd.pb_wb_midnumlet = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "MidLetter":
                cpd = CodePointData()
                cpd.pb_wb_midletter = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "MidNum":
                cpd = CodePointData()
                cpd.pb_wb_midnum = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "Numeric":
                cpd = CodePointData()
                cpd.pb_wb_numeric = True
                CodePointRange(cprng[0], cprng[1], cpd)
            elif prop == "ExtendNumLet":
                cpd = CodePointData()
                cpd.pb_wb_extendnumlet = True
                CodePointRange(cprng[0], cprng[1], cpd)


def resolve_case_mappings():
    global ud_codepoints
    global ud_case_mappings
    global ud_case_mapping_max_length

    for cpr in ud_codepoints:
        if cpr.cp_last > cpr.cp_first:
            # No case mappings in ranges expected, ever
            continue
        cp = cpr.cp_first
        cpd = cpr.data

        # Uppercase_Mapping
        ucase_codes = []
        if hasattr(cpd, "uppercase_mapping"):
            ucase_codes = cpd.uppercase_mapping
        if len(ucase_codes) > 0 and (len(ucase_codes) > 1 or ucase_codes[0] != cp):
            cpd.uppercase_mapping_offset = len(ud_case_mappings)
            cpd.uppercase_mapping_length = len(ucase_codes)
            ud_case_mappings = ud_case_mappings + ucase_codes
        elif (
            hasattr(cpd, "simple_uppercase_mapping")
            and cpd.simple_uppercase_mapping != cp
        ):
            cpd.uppercase_mapping_offset = len(ud_case_mappings)
            cpd.uppercase_mapping_length = 1
            ud_case_mappings.append(cpd.simple_uppercase_mapping)
            ucase_codes = [cpd.simple_uppercase_mapping]
        else:
            ucase_codes = []
        if len(ucase_codes) > ud_case_mapping_max_length:
            ud_case_mapping_max_length = len(ucase_codes)

        # Lowercase_Mapping
        lcase_codes = []
        if hasattr(cpd, "lowercase_mapping"):
            lcase_codes = cpd.lowercase_mapping
        if len(lcase_codes) > 0 and (len(lcase_codes) > 1 or lcase_codes[0] != cp):
            cpd.lowercase_mapping_offset = len(ud_case_mappings)
            cpd.lowercase_mapping_length = len(lcase_codes)
            ud_case_mappings = ud_case_mappings + lcase_codes
        elif (
            hasattr(cpd, "simple_lowercase_mapping")
            and cpd.simple_lowercase_mapping != cp
        ):
            cpd.lowercase_mapping_offset = len(ud_case_mappings)
            cpd.lowercase_mapping_length = 1
            ud_case_mappings.append(cpd.simple_lowercase_mapping)
            lcase_codes = [cpd.simple_lowercase_mapping]
        else:
            lcase_codes = []
        if len(lcase_codes) > ud_case_mapping_max_length:
            ud_case_mapping_max_length = len(lcase_codes)

        # Case_Folding
        cfold_codes = []
        if hasattr(cpd, "case_folding"):
            cfold_codes = cpd.case_folding
        if len(ucase_codes) > 0 and cfold_codes == ucase_codes:
            cpd.casefold_mapping_length = cpd.uppercase_mapping_length
            cpd.casefold_mapping_offset = cpd.uppercase_mapping_offset
        elif len(lcase_codes) > 0 and cfold_codes == lcase_codes:
            cpd.casefold_mapping_length = cpd.lowercase_mapping_length
            cpd.casefold_mapping_offset = cpd.lowercase_mapping_offset
        elif len(cfold_codes) > 0 and (len(cfold_codes) > 1 or cfold_codes[0] != cp):
            cpd.casefold_mapping_offset = len(ud_case_mappings)
            cpd.casefold_mapping_length = len(cfold_codes)
            ud_case_mappings = ud_case_mappings + cfold_codes
        if len(cfold_codes) > ud_case_mapping_max_length:
            ud_case_mapping_max_length = len(cfold_codes)


def expand_decompositions():
    global ud_codepoints
    global ud_codepoints_index
    global ud_decompositions
    global ud_decomposition_max_length

    # Record first decompositions in ud_decompositions table
    for cpr in ud_codepoints:
        cpd = cpr.data

        if not hasattr(cpd, "decomposition_first") or len(cpd.decomposition_first) == 0:
            continue

        dc = cpd.decomposition_first
        cpd.decomposition_offset = len(ud_decompositions)
        cpd.decomposition_length = len(dc)
        ud_decompositions = ud_decompositions + dc
        if len(dc) > ud_decomposition_max_length:
            ud_decomposition_max_length = len(dc)

    # Expand all decompositions
    for cpr in ud_codepoints:
        if cpr.cp_last > cpr.cp_first:
            # No decompositions in ranges expected, ever
            continue
        cpd = cpr.data

        if not hasattr(cpd, "decomposition_first") or len(cpd.decomposition_first) == 0:
            continue

        dc_type = None
        if hasattr(cpd, "decomposition_type"):
            dc_type = cpd.decomposition_type

        # Canonical
        dc = []

        finished = False
        changed = False
        if dc_type is None:
            dc = cpd.decomposition_first
        else:
            finished = True
            changed = True

        while not finished:
            finished = True

            dc_new = []
            for dcp in dc:
                if dcp not in ud_codepoints_index:
                    dc_new.append(dcp)
                    continue

                scpr = ud_codepoints_index[dcp]
                scpd = scpr.data

                if (
                    hasattr(scpd, "decomposition_type")
                    or not hasattr(scpd, "decomposition_first")
                    or (
                        len(scpd.decomposition_first) == 1
                        and scpd.decomposition_first[0] == dcp
                    )
                ):
                    dc_new.append(dcp)
                    continue

                finished = False
                changed = True
                dc_new = dc_new + scpd.decomposition_first

            if not finished:
                dc = dc_new

        if not changed:
            if hasattr(cpd, "decomposition_offset"):
                cpd.decomposition_full_offset = cpd.decomposition_offset
                cpd.decomposition_full_length = cpd.decomposition_length
        elif len(dc) == 0:
            pass
        else:
            cpd.decomposition_full_offset = len(ud_decompositions)
            cpd.decomposition_full_length = len(dc)
            ud_decompositions = ud_decompositions + dc
            if len(dc) > ud_decomposition_max_length:
                ud_decomposition_max_length = len(dc)

        dc_c = dc

        # Compatibility
        dc = cpd.decomposition_first

        finished = False
        changed = False
        while not finished:
            finished = True

            dc_new = []
            for dcp in dc:
                if dcp not in ud_codepoints_index:
                    dc_new.append(dcp)
                    continue

                scpr = ud_codepoints_index[dcp]
                scpd = scpr.data

                if not hasattr(scpd, "decomposition_first") or (
                    len(scpd.decomposition_first) == 1
                    and scpd.decomposition_first[0] == dcp
                ):
                    dc_new.append(dcp)
                    continue

                finished = False
                changed = True
                dc_new = dc_new + scpd.decomposition_first

            if not finished:
                dc = dc_new

        if not changed:
            if hasattr(cpd, "decomposition_offset"):
                cpd.decomposition_full_k_offset = cpd.decomposition_offset
                cpd.decomposition_full_k_length = cpd.decomposition_length
        elif dc == dc_c:
            cpd.decomposition_full_k_offset = cpd.decomposition_full_offset
            cpd.decomposition_full_k_length = cpd.decomposition_full_length
        else:
            cpd.decomposition_full_k_offset = len(ud_decompositions)
            cpd.decomposition_full_k_length = len(dc)
            ud_decompositions = ud_decompositions + dc
            if len(dc) > ud_decomposition_max_length:
                ud_decomposition_max_length = len(dc)


def derive_canonical_compositions():
    global ud_codepoints
    global ud_decompositions
    global ud_composition_exclusions
    global ud_composition_pairs
    global ud_composition_composites
    global ud_compositions
    global ud_composition_primaries
    global ud_compositions_max_per_starter

    for cpr in ud_codepoints:
        if cpr.cp_last > cpr.cp_first:
            # No compositions in ranges expected, ever
            continue
        cp = cpr.cp_first
        cpd = cpr.data

        if not hasattr(cpd, "decomposition_full_offset"):
            continue

        # Skip singleton decompositions
        if len(cpd.decomposition_first) < 2:
            continue

        # Skip non-starter decompositions
        dc_offset = cpd.decomposition_full_offset
        dc_len = cpd.decomposition_full_length
        dc = ud_decompositions[dc_offset:(dc_offset + dc_len)]

        scpr = ud_codepoints_index[dc[0]]
        scpd = scpr.data
        if (
            hasattr(scpd, "canonical_combining_class")
            and scpd.canonical_combining_class > 0
        ):
            continue

        # Skip composition exclusions
        if cp in ud_composition_exclusions:
            continue

        dc = cpd.decomposition_first

        # Record all alternative pairs for each starter
        if not dc[0] in ud_composition_pairs:
            mp = [(dc[1], cp)]
            ud_composition_pairs[dc[0]] = mp
        else:
            mp = ud_composition_pairs[dc[0]]
            mp.append((dc[1], cp))

            if len(mp) > ud_compositions_max_per_starter:
                ud_compositions_max_per_starter = len(mp)

    # Compose lookup tables
    for cpr in ud_codepoints:
        if cpr.cp_last > cpr.cp_first:
            # No compositions in ranges expected, ever
            continue
        cp = cpr.cp_first
        cpd = cpr.data

        if cp not in ud_composition_pairs:
            continue

        def mp_key_func(a):
            return a[0]

        mp = ud_composition_pairs[cp]
        mp.sort(key=mp_key_func)

        cpd.composition_offset = len(ud_compositions)
        cpd.composition_count = len(mp)

        ud_compositions = ud_compositions + [p[0] for p in mp]
        ud_composition_primaries = ud_composition_primaries + [p[1] for p in mp]


def create_cp_range_index():
    global ud_codepoints
    global ud_codepoints_index

    for cpr in ud_codepoints:
        ud_codepoints_index[cpr.cp_first] = cpr


def update_cp_index_tables(cp_first, cp_last, cp_pos):
    global ud_codepoints_index8
    global ud_codepoints_index16
    global ud_codepoints_index16_reused
    global ud_codepoints_index16_offsets
    global ud_codepoints_index16_blocks
    global ud_codepoints_index24
    global ud_codepoints_index24_reused
    global ud_codepoints_index24_offsets
    global ud_codepoints_index24_blocks
    global ud_codepoints_index32
    global ud_codepoints_index32_reused
    global ud_codepoints_index32_offsets
    global ud_codepoints_index32_blocks

    cp_range = range(cp_first, cp_last + 1)

    id16_block = None
    id24_block = None
    id32_block = None
    first16 = True
    first24 = True
    first32 = True

    last_rcp = cp_last
    for rcp in cp_range:
        # Index for first 8 bits of code point
        id8_idx = rcp >> 24
        if id8_idx in ud_codepoints_index8:
            id16_block = ud_codepoints_index8[id8_idx]
        elif (
            id16_block is not None
            and not first16
            and ((last_rcp & 0xFFFFFF) == 0xFFFFFF or (rcp >> 24) != (last_rcp >> 24))
        ):
            ud_codepoints_index8[id8_idx] = id16_block
            if id16_block not in ud_codepoints_index16_reused:
                ud_codepoints_index16_reused[id16_block] = 1
            ud_codepoints_index16_reused[id16_block] += 1
        else:
            first16 = False
            id16_block = ud_codepoints_index16_blocks
            ud_codepoints_index8[id8_idx] = id16_block
            ud_codepoints_index16_offsets[id16_block] = rcp & (((1 << 8) - 1) << 24)
            ud_codepoints_index16_blocks += 1

        # Index for first 16 bits of code point
        id16_idx = (id16_block << 8) + ((rcp >> 16) & 0xFF)
        if id16_idx in ud_codepoints_index16:
            id24_block = ud_codepoints_index16[id16_idx]
        elif (
            id24_block is not None
            and not first24
            and ((last_rcp & 0xFFFF) == 0xFFFF or (rcp >> 16) != (last_rcp >> 16))
        ):
            ud_codepoints_index16[id16_idx] = id24_block
            if id24_block not in ud_codepoints_index24_reused:
                ud_codepoints_index24_reused[id24_block] = 1
            ud_codepoints_index24_reused[id24_block] += 1
        else:
            first24 = False
            id24_block = ud_codepoints_index24_blocks
            ud_codepoints_index16[id16_idx] = id24_block
            ud_codepoints_index24_offsets[id24_block] = rcp & (((1 << 16) - 1) << 16)
            ud_codepoints_index24_blocks += 1

        # Index for first 24 bits of code point
        id24_idx = (id24_block << 8) + ((rcp >> 8) & 0xFF)
        if id24_idx in ud_codepoints_index24:
            id32_block = ud_codepoints_index24[id24_idx]
        elif (
            id32_block is not None
            and not first32
            and ((last_rcp & 0xFF) == 0xFF or (rcp >> 8) != (last_rcp >> 8))
        ):
            ud_codepoints_index24[id24_idx] = id32_block
            if id32_block not in ud_codepoints_index32_reused:
                ud_codepoints_index32_reused[id32_block] = 1
            ud_codepoints_index32_reused[id32_block] += 1
        else:
            first32 = False
            id32_block = ud_codepoints_index32_blocks
            ud_codepoints_index24[id24_idx] = id32_block
            ud_codepoints_index32_offsets[id32_block] = rcp & (((1 << 24) - 1) << 8)
            ud_codepoints_index32_blocks += 1

        # Index for first 32 bits of code point
        id32_idx = (id32_block << 8) + (rcp & 0xFF)
        ud_codepoints_index32[id32_idx] = cp_pos


def create_cp_index_tables():
    global ud_codepoints

    # Create code point index
    for n in range(0, len(ud_codepoints)):
        cpr = ud_codepoints[n]
        cp_first = cpr.cp_first
        cp_last = cpr.cp_last

        update_cp_index_tables(cp_first, cp_last, n)


def get_general_category_def(gc):
    return "UNICODE_GENERAL_CATEGORY_%s" % gc.upper()


def decomposition_type_def(dt):
    return "UNICODE_DECOMPOSITION_TYPE_%s" % dt.upper()


def print_list(code_list):
    last = len(code_list) - 1
    n = 0
    print("\t", end="")
    for code in code_list:
        print("0x%05x" % code, end="")
        if n == last:
            break
        print(",", end="")

        n += 1
        if (n % 8) == 0:
            print("")
            print("\t", end="")
            if (n % 10) == 0:
                print("// INDEX %u" % n)
                print("\t", end="")
        else:
            print(" ", end="")


def print_top_message():
    global ucd_dir
    global source_files

    print("/* This file is automatically generated by unicode-ucd-compile.py from:")
    for sf in source_files:
        print("     %s/%s" % (ucd_dir, sf))
    print(" */")
    print("")


def write_tables_h():
    global output_dir
    global ud_decomposition_max_length
    global ud_compositions_max_per_starter
    global ud_case_mapping_max_length

    orig_stdout = sys.stdout

    with open(output_dir + "/unicode-data-tables.h", mode="w", encoding="utf-8") as fd:
        sys.stdout = fd

        print("#ifndef UNICODE_DATA_TABLES_H")
        print("#define UNICODE_DATA_TABLES_H")
        print("")
        print_top_message()
        print('#include "unicode-data-types.h"')
        print("")
        print(
            "#define UNICODE_DECOMPOSITION_MAX_LENGTH %s" % ud_decomposition_max_length
        )
        print(
            "#define UNICODE_COMPOSITIONS_MAX_PER_STARTER %s"
            % ud_compositions_max_per_starter
        )
        print("#define UNICODE_CASE_MAPPING_MAX_LENGTH %s" % ud_case_mapping_max_length)
        print("")
        print("extern const struct unicode_code_point_data unicode_code_points[];")
        print("")
        print("extern const uint8_t unicode_code_points_index8[];")
        print("extern const uint8_t unicode_code_points_index16[];")
        print("extern const uint16_t unicode_code_points_index24[];")
        print("extern const uint16_t unicode_code_points_index32[];")
        print("")
        print("extern const uint32_t unicode_decompositions[];")
        print("")
        print("extern const uint32_t unicode_compositions[];")
        print("extern const uint32_t unicode_composition_primaries[];")
        print("")
        print("extern const uint32_t unicode_case_mappings[];")
        print("")
        print("#endif")

    sys.stdout = orig_stdout


def write_tables_c():
    global output_dir
    global ud_codepoints
    global ud_decompositions
    global ud_compositions
    global ud_composition_primaries
    global ud_case_mappings

    orig_stdout = sys.stdout

    with open(output_dir + "/unicode-data-tables.c", mode="w", encoding="utf-8") as fd:
        sys.stdout = fd
        print_top_message()

        print('#include "lib.h"')
        print('#include "unicode-data-tables.h"')
        print("")
        print("const struct unicode_code_point_data unicode_code_points[] = {")
        print("\t{ // [0000] <invalid>")
        print("\t\t.general_category = UNICODE_GENERAL_CATEGORY_INVALID,")
        print("\t},")
        print("\t{ // [0001] <unassigned>")
        print("\t\t.general_category = UNICODE_GENERAL_CATEGORY_CN,")
        print("\t},")
        n = 2
        for cpr in ud_codepoints:
            cpd = cpr.data

            if cpr.cp_last > cpr.cp_first:
                range_str = "U+%04X..U+%04X" % (cpr.cp_first, cpr.cp_last)
            else:
                range_str = "U+%04X" % (cpr.cp_first)
            print("\t{ // [%04X] %s: %s" % (n, range_str, cpd.name))
            n = n + 1

            print(
                "\t\t.general_category = %s,"
                % get_general_category_def(cpd.general_category)
            )
            if (
                hasattr(cpd, "canonical_combining_class")
                and cpd.canonical_combining_class > 0
            ):
                print(
                    "\t\t.canonical_combining_class = %u,"
                    % cpd.canonical_combining_class
                )
            if (
                hasattr(cpd, "nfd_quick_check")
                or hasattr(cpd, "nfkd_quick_check")
                or hasattr(cpd, "nfc_quick_check")
                or hasattr(cpd, "nfkc_quick_check")
            ):
                print("\t\t.nf_quick_check = (", end="")
                if hasattr(cpd, "nfkc_quick_check"):
                    if cpd.nfkc_quick_check == "N":
                        print("UNICODE_NFKC_QUICK_CHECK_NO", end="")
                    elif cpd.nfkc_quick_check == "M":
                        print("UNICODE_NFKC_QUICK_CHECK_MAYBE", end="")
                if hasattr(cpd, "nfkc_quick_check") and hasattr(cpd, "nfc_quick_check"):
                    print(" |")
                    print("\t\t\t\t   ", end="")
                if hasattr(cpd, "nfc_quick_check"):
                    if cpd.nfc_quick_check == "N":
                        print("UNICODE_NFC_QUICK_CHECK_NO", end="")
                    elif cpd.nfc_quick_check == "M":
                        print("UNICODE_NFC_QUICK_CHECK_MAYBE", end="")
                if (
                    hasattr(cpd, "nfkc_quick_check") or hasattr(cpd, "nfc_quick_check")
                ) and hasattr(cpd, "nfkd_quick_check"):
                    print(" |")
                    print("\t\t\t\t   ", end="")
                if hasattr(cpd, "nfkd_quick_check"):
                    if cpd.nfkd_quick_check == "N":
                        print("UNICODE_NFKD_QUICK_CHECK_NO", end="")
                    elif cpd.nfkd_quick_check == "M":
                        print("UNICODE_NFKD_QUICK_CHECK_MAYBE", end="")
                if (
                    hasattr(cpd, "nfkc_quick_check")
                    or hasattr(cpd, "nfc_quick_check")
                    or hasattr(cpd, "nfkd_quick_check")
                ) and hasattr(cpd, "nfd_quick_check"):
                    print(" |")
                    print("\t\t\t\t   ", end="")
                if hasattr(cpd, "nfd_quick_check"):
                    if cpd.nfd_quick_check == "N":
                        print("UNICODE_NFD_QUICK_CHECK_NO", end="")
                    elif cpd.nfd_quick_check == "M":
                        print("UNICODE_NFD_QUICK_CHECK_MAYBE", end="")
                print("),")
            if hasattr(cpd, "decomposition_type"):
                print(
                    "\t\t.decomposition_type = %s,"
                    % decomposition_type_def(cpd.decomposition_type)
                )
            if hasattr(cpd, "decomposition_length"):
                print("\t\t.decomposition_first_length = %u," % cpd.decomposition_length)
                print("\t\t.decomposition_first_offset = %u," % cpd.decomposition_offset)
            if hasattr(cpd, "decomposition_full_length"):
                print(
                    "\t\t.decomposition_full_length = %u,"
                    % cpd.decomposition_full_length
                )
                print(
                    "\t\t.decomposition_full_offset = %u,"
                    % cpd.decomposition_full_offset
                )
            if hasattr(cpd, "decomposition_full_k_length"):
                print(
                    "\t\t.decomposition_full_k_length = %u,"
                    % cpd.decomposition_full_k_length
                )
                print(
                    "\t\t.decomposition_full_k_offset = %u,"
                    % cpd.decomposition_full_k_offset
                )
            if hasattr(cpd, "composition_count"):
                print("\t\t.composition_count = %u," % cpd.composition_count)
                print("\t\t.composition_offset = %u," % cpd.composition_offset)
            if (
                hasattr(cpd, "lowercase_mapping_length")
                and cpd.lowercase_mapping_length > 0
            ):
                print(
                    "\t\t.lowercase_mapping_length = %s," % cpd.lowercase_mapping_length
                )
                print(
                    "\t\t.lowercase_mapping_offset = %s," % cpd.lowercase_mapping_offset
                )
            if (
                hasattr(cpd, "uppercase_mapping_length")
                and cpd.uppercase_mapping_length > 0
            ):
                print(
                    "\t\t.uppercase_mapping_length = %s," % cpd.uppercase_mapping_length
                )
                print(
                    "\t\t.uppercase_mapping_offset = %s," % cpd.uppercase_mapping_offset
                )
            if (
                hasattr(cpd, "casefold_mapping_length")
                and cpd.casefold_mapping_length > 0
            ):
                print("\t\t.casefold_mapping_length = %s," % cpd.casefold_mapping_length)
                print("\t\t.casefold_mapping_offset = %s," % cpd.casefold_mapping_offset)
            if hasattr(cpd, "simple_titlecase_mapping"):
                print(
                    "\t\t.simple_titlecase_mapping = 0x%04X,"
                    % cpd.simple_titlecase_mapping
                )
            if hasattr(cpd, "pb_g_white_space"):
                print("\t\t.pb_g_white_space = TRUE,")
            if hasattr(cpd, "pb_i_pattern_white_space"):
                print("\t\t.pb_i_pattern_white_space = TRUE,")
            if hasattr(cpd, "pb_m_quotation_mark"):
                print("\t\t.pb_m_quotation_mark = TRUE,")
            if hasattr(cpd, "pb_m_dash"):
                print("\t\t.pb_m_dash = TRUE,")
            if hasattr(cpd, "pb_m_sentence_terminal"):
                print("\t\t.pb_m_sentence_terminal = TRUE,")
            if hasattr(cpd, "pb_m_terminal_punctuation"):
                print("\t\t.pb_m_terminal_punctuation = TRUE,")
            if hasattr(cpd, "pb_wb_cr"):
                print("\t\t.pb_wb_cr = TRUE,")
            if hasattr(cpd, "pb_wb_lf"):
                print("\t\t.pb_wb_lf = TRUE,")
            if hasattr(cpd, "pb_wb_newline"):
                print("\t\t.pb_wb_newline = TRUE,")
            if hasattr(cpd, "pb_wb_extend"):
                print("\t\t.pb_wb_extend = TRUE,")
            if hasattr(cpd, "pb_wb_zwj"):
                print("\t\t.pb_wb_zwj = TRUE,")
            if hasattr(cpd, "pb_wb_regional_indicator"):
                print("\t\t.pb_wb_regional_indicator = TRUE,")
            if hasattr(cpd, "pb_wb_format"):
                print("\t\t.pb_wb_format = TRUE,")
            if hasattr(cpd, "pb_wb_katakana"):
                print("\t\t.pb_wb_katakana = TRUE,")
            if hasattr(cpd, "pb_wb_hebrew_letter"):
                print("\t\t.pb_wb_hebrew_letter = TRUE,")
            if hasattr(cpd, "pb_wb_aletter"):
                print("\t\t.pb_wb_aletter = TRUE,")
            if hasattr(cpd, "pb_wb_single_quote"):
                print("\t\t.pb_wb_single_quote = TRUE,")
            if hasattr(cpd, "pb_wb_double_quote"):
                print("\t\t.pb_wb_double_quote = TRUE,")
            if hasattr(cpd, "pb_wb_midnumlet"):
                print("\t\t.pb_wb_midnumlet = TRUE,")
            if hasattr(cpd, "pb_wb_midletter"):
                print("\t\t.pb_wb_midletter = TRUE,")
            if hasattr(cpd, "pb_wb_midnum"):
                print("\t\t.pb_wb_midnum = TRUE,")
            if hasattr(cpd, "pb_wb_numeric"):
                print("\t\t.pb_wb_numeric = TRUE,")
            if hasattr(cpd, "pb_wb_extendnumlet"):
                print("\t\t.pb_wb_extendnumlet = TRUE,")
            print("\t},")
        print("};")
        print("")
        # Code points index8
        print("const uint8_t unicode_code_points_index8[] = {")
        print("\t", end="")
        for n in range(0, 256):
            if n in ud_codepoints_index8:
                print("0x%02x" % ud_codepoints_index8[n], end="")
            else:
                print("0x00", end="")
            if n == 255:
                break
            print(",", end="")

            if ((n + 1) % 8) == 0:
                print("\n\t", end="")
            else:
                print(" ", end="")
        print(",")
        print("};")
        print("")
        # Code points index16
        print("const uint8_t unicode_code_points_index16[] = {")
        print("\t// Block 0x00: <invalid>")
        print("\t", end="")
        last = (1 << 8) - 1
        for n in range(0 << 8, last + 1):
            print("0x00", end="")
            if n == last:
                break
            print(",", end="")

            if ((n + 1) % 8) == 0:
                print("\n\t", end="")
            else:
                print(" ", end="")
        print(",")
        print("\t", end="")
        last = (ud_codepoints_index16_blocks << 8) - 1
        for n in range((1 << 8), last + 1):
            if (n & ((1 << 8) - 1)) == 0:
                blk_id = n >> 8
                blk_offset = ud_codepoints_index16_offsets[blk_id]
                blk_end = blk_offset + (1 << 24) - 1
                print(
                    "// Block 0x%02X: U+%06X..U+%06X" % (blk_id, blk_offset, blk_end),
                    end="",
                )
                if blk_id in ud_codepoints_index16_reused:
                    print(
                        " (used %u times)" % ud_codepoints_index16_reused[blk_id], end=""
                    )
                print("")
                print("\t", end="")
            if n in ud_codepoints_index16:
                print("0x%02x" % ud_codepoints_index16[n], end="")
            elif ud_codepoints_index16_offsets[n >> 8] + ((n & 0xFF) << 16) > 0x10FFFF:
                print("0x00", end="")
            else:
                print("0x01", end="")
            if n == last:
                break
            print(",", end="")

            if ((n + 1) % 8) == 0:
                print("")
                print("\t", end="")
            else:
                print(" ", end="")
        print("")
        print("};")
        print("")
        # Code points index24
        print("const uint16_t unicode_code_points_index24[] = {")
        print("\t// Block 0x00: <invalid>")
        print("\t", end="")
        last = (1 << 8) - 1
        for n in range((0 << 8), last + 1):
            print("0x000", end="")
            if n == last:
                break
            print(",", end="")

            if ((n + 1) % 8) == 0:
                print("")
                print("\t", end="")
            else:
                print(" ", end="")
        print(",")
        print("\t// Block 0x01: <unassigned>")
        print("\t", end="")
        last = (2 << 8) - 1
        for n in range((1 << 8), last + 1):
            print("0x001", end="")
            if n == last:
                break
            print(",", end="")

            if ((n + 1) % 8) == 0:
                print("")
                print("\t", end="")
            else:
                print(" ", end="")
        print(",")
        print("\t", end="")
        last = (ud_codepoints_index24_blocks << 8) - 1
        for n in range((2 << 8), last + 1):
            if (n & ((1 << 8) - 1)) == 0:
                blk_id = n >> 8
                blk_offset = ud_codepoints_index24_offsets[blk_id]
                blk_end = blk_offset + (1 << 16) - 1
                print(
                    "// Block 0x%04X: U+%06X..U+%06X" % (blk_id, blk_offset, blk_end),
                    end="",
                )
                if blk_id in ud_codepoints_index24_reused:
                    print(
                        " (used %u times)" % ud_codepoints_index24_reused[blk_id], end=""
                    )
                print("")
                print("\t", end="")
            if n in ud_codepoints_index24:
                print("0x%03x" % ud_codepoints_index24[n], end="")
            else:
                print("0x001", end="")
            if n == last:
                break
            print(",", end="")

            if ((n + 1) % 8) == 0:
                print("")
                print("\t", end="")
            else:
                print(" ", end="")
        print(",")
        print("};")
        print("")
        # Code points index32
        print("const uint16_t unicode_code_points_index32[] = {")
        print("\t// Block 0x000: <invalid>")
        print("\t", end="")
        last = (1 << 8) - 1
        for n in range(0 << 8, last + 1):
            print("0x0000", end="")
            if n == last:
                break
            print(",", end="")

            if ((n + 1) % 8) == 0:
                print("")
                print("\t", end="")
            else:
                print(" ", end="")
        print(",")
        print("\t// Block 0x001: <unassigned>")
        print("\t", end="")
        last = (2 << 8) - 1
        for n in range(1 << 8, last + 1):
            print("0x0001", end="")
            if n == last:
                break
            print(",", end="")

            if ((n + 1) % 8) == 0:
                print("")
                print("\t", end="")
            else:
                print(" ", end="")
        print(",")
        print("\t", end="")
        last = (ud_codepoints_index32_blocks << 8) - 1
        for n in range(2 << 8, last + 1):
            if (n & ((1 << 8) - 1)) == 0:
                blk_id = n >> 8
                blk_offset = ud_codepoints_index32_offsets[blk_id]
                blk_end = blk_offset + (1 << 8) - 1
                print(
                    "// Block 0x%04X: U+%06X - U+%06X" % (blk_id, blk_offset, blk_end),
                    end="",
                )
                if blk_id in ud_codepoints_index32_reused:
                    print(
                        " (used %u times)" % ud_codepoints_index32_reused[blk_id], end=""
                    )
                print("")
                print("\t", end="")
            if n in ud_codepoints_index32:
                print("0x%04x" % (ud_codepoints_index32[n] + 2), end="")
            else:
                print("0x0001", end="")
            if n == last:
                break
            print(",", end="")

            if ((n + 1) % 8) == 0:
                print("")
                print("\t", end="")
            else:
                print(" ", end="")
        print(",")
        print("};")
        print("")
        print("const uint32_t unicode_decompositions[] = {")
        print_list(ud_decompositions)
        print(",")
        print("};")
        print("")
        print("const uint32_t unicode_compositions[] = {")
        print_list(ud_compositions)
        print(",")
        print("};")
        print("")
        print("const uint32_t unicode_composition_primaries[] = {")
        print_list(ud_composition_primaries)
        print(",")
        print("};")
        print("")
        print("const uint32_t unicode_case_mappings[] = {")
        print_list(ud_case_mappings)
        print(",")
        print("};")

    sys.stdout = orig_stdout


def write_types_h():
    global output_dir
    global ud_decomposition_type_names

    orig_stdout = sys.stdout

    with open(output_dir + "/unicode-data-types.h", mode="w", encoding="utf-8") as fd:
        sys.stdout = fd

        print("#ifndef UNICODE_DATA_TYPES_H")
        print("#define UNICODE_DATA_TYPES_H")
        print("")
        print_top_message()
        print('#include "unicode-data-static.h"')
        print("")
        print("/* Decomposition_Type */")
        print("enum unicode_decomposition_type {")
        print("\t/* Canonical */")
        print("\tUNICODE_DECOMPOSITION_TYPE_CANONICAL = 0,")
        for dt in ud_decomposition_type_names:
            dt_uc = dt.upper()

            if dt_uc == "CANONICAL":
                continue

            print("\t/* <%s> */" % dt)
            print("\tUNICODE_DECOMPOSITION_TYPE_%s," % dt_uc)
        print("};")
        print("")
        print("/* Decomposition_Type */")
        print("enum unicode_decomposition_type")
        print("unicode_decomposition_type_from_string(const char *str);")
        print("")
        print("#endif")

    sys.stdout = orig_stdout


def write_types_c():
    global output_dir
    global ud_decomposition_type_names

    orig_stdout = sys.stdout

    with open(output_dir + "/unicode-data-types.c", mode="w", encoding="utf-8") as fd:
        sys.stdout = fd

        print_top_message()
        print('#include "lib.h"')
        print('#include "unicode-data-types.h"')
        print("")
        print("/* Decomposition_Type */")
        print("enum unicode_decomposition_type")
        print("unicode_decomposition_type_from_string(const char *str)")
        print("{")
        print("\t/* Canonical */")
        print('\tif (strcasecmp(str, "Canonical") == 0)')
        print("\t\treturn UNICODE_DECOMPOSITION_TYPE_CANONICAL;")
        for dt in ud_decomposition_type_names:
            dt_uc = dt.upper()

            if dt_uc == "CANONICAL":
                continue

            print("\t/* <%s> */" % dt)
            print('\telse if (strcasecmp(str, "%s") == 0)' % dt)
            print("\t\treturn UNICODE_DECOMPOSITION_TYPE_%s;" % dt_uc)
        print("")
        print("\treturn UNICODE_DECOMPOSITION_TYPE_CANONICAL;")
        print("}")

    sys.stdout = orig_stdout


def main():
    global ucd_dir
    global output_dir
    global source_files

    """Entry point."""
    parser = argparse.ArgumentParser(
        prog="unicode-ucd-compile.py",
        description="Compile the Unicode Character Database files into C code",
    )
    parser.add_argument(
        "ucd-dir",
        type=str,
        help="Directory containing the UCD files",
    )
    parser.add_argument(
        "output-dir",
        type=str,
        help="Output directory where the C header and source files are written",
    )
    args = parser.parse_args()

    ucd_dir = getattr(args, "ucd-dir")
    output_dir = getattr(args, "output-dir")

    read_ucd_files()
    source_files.sort()

    create_cp_range_index()
    resolve_case_mappings()
    expand_decompositions()
    derive_canonical_compositions()

    create_cp_index_tables()

    write_tables_h()
    write_tables_c()
    write_types_h()
    write_types_c()


if __name__ == "__main__":
    main()
