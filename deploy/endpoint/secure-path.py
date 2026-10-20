#!/usr/bin/env python3
"""Reject pre-existing untrusted installation paths before any privileged writes."""
import os, pathlib, stat, sys
for value in sys.argv[1:]:
    path=pathlib.Path(value)
    if not path.is_absolute():raise SystemExit('Installation paths must be absolute')
    for item in [path,*path.parents]:
        try:meta=item.lstat()
        except FileNotFoundError:continue
        if stat.S_ISLNK(meta.st_mode) or meta.st_uid!=0 or meta.st_mode & 0o022:
            raise SystemExit(f'Unsafe installation path: {item}; requires root ownership and no group/other writes or symbolic links')
