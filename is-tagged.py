#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Checks if the current revision of the repository is a tagged revision,
    but not 'tip'.

    usage:
    python is-tagged.py [/path/to/repo]
    if no path is given, the current working directory will be used.

    Exit status:
      0 if the current revision is a tagged version OR
        if the current revision was used for signing/tagging OR
        if path is not a Mercurial repository OR
        if module import should fail for some reason
      1 if the current revision has no tag, except 'tip'
"""
import re
import sys
try:
    from mercurial import hg, ui
except ImportError:  # no Mercurial at all
    sys.exit(0)
try:
    from mercurial.error import Abort, RepoError
except ImportError:
    try:
        from mercurial.repo import RepoError
        from mercurial.util import Abort
    except ImportError:  # something old/new?
        sys.exit(0)

RE = r'^Added\s(?:signature|tag)\s(?:[\w\.]+\s)?for\schangeset\s[\da-f]{12,}$'


def main():
    if len(sys.argv) > 1:
        path = sys.argv[1].strip()
    else:
        path = '.'
    try:
        repo = hg.repository(ui.ui(), path)
    except (Abort, RepoError):  # no/bad repo? no extra version info
        return 0
    parents_id = repo.dirstate.parents()[0]
    ctx = repo.changectx(parents_id)
    if re.match(RE, ctx.description()):  # tag or sig was added for a release
        return 0
    for tag, nodeid in repo.tags().iteritems():
        if tag != 'tip' and parents_id == nodeid:  # tagged
            return 0
    # not tagged
    return 1


if __name__ == '__main__':
    sys.exit(main())
