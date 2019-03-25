#!/usr/bin/env python3
"""
This file is part of Mbed TLS (https://tls.mbed.org)

Copyright (c) 2019, Arm Limited, All Rights Reserved

Purpose

This script combines the change logs (ChangeLog) from multiple branches and
generates a combined change log, suitable for including in release notes
Note: requires Python 3.
"""

import os
import argparse
import logging
import codecs
import sys
import subprocess
import collections

_changes = {}

def _get_changelog(git_rev):
    changelog = git_rev + ":ChangeLog"
    worktree_process = subprocess.Popen(
        ["git", "show", changelog],
        #cwd=self.repo_path,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT
    )
    worktree_output, _ = worktree_process.communicate()
    output = worktree_output.decode("utf-8")
    if worktree_process.returncode != 0:
        raise Exception("Showing ChangeLog failed; aborting")
    return output

def _parse_changelog(label, git_rev):
    """For a given git rev, add an entry to the dictionary of changes for that
    git rev referencable by the given label."""
    changelog = _get_changelog(git_rev).splitlines()
    is_parsing_version = False
    is_parsing_entry = False
    section = None
    for line in changelog:
        begin_feature = str.startswith(line, '=')
        if is_parsing_version:
            if begin_feature:
                break
            elif str.startswith(line, 'Security') or \
                 str.startswith(line, 'Features') or \
                 str.startswith(line, 'API Changes') or \
                 str.startswith(line, 'New deprecations') or \
                 str.startswith(line, 'Bugfix') or \
                 str.startswith(line, 'Changes'):
                section = line
                _changes[label][section] = []
            elif str.startswith(line.strip(), '*'):
                entry = line.strip()[2:]
                _changes[label][section].append(entry)
                is_parsing_entry = True
            elif is_parsing_entry and line.strip() != '':
                _changes[label][section][-1] += ' ' + line.strip()
        elif begin_feature:
            is_parsing_version = True
            _changes[label] = collections.OrderedDict()

def _combine_changelog():
    combo = collections.OrderedDict()
    # {'Feature': {'Remove a dupe.':'(2.7, 2.14)'}}
    for version in _changes:
        for section in _changes[version]:
            if not section in combo:
                combo[section] = collections.OrderedDict()
            for entry in _changes[version][section]:
                if entry in combo[section]:
                    start = combo[section][entry][:-1]
                    combo[section][entry] = start + ', ' + version + ')'
                else:
                    combo[section][entry] = '(' + version + ')'
    return combo

def _dump_changelog(combo):
    for section in combo:
        print(section)
        for entry in combo[section]:
            print('   *', combo[section][entry], entry)
        print()

def run_main():
    parser = argparse.ArgumentParser(
        description=(
            "This script combines multiple change logs into a unified "
            "change log. "
            "Note: requires Python 3."
        )
    )
    parser.add_argument(
        "-o", "--output", type=str, help="Path to optional output log",
    )
    check_args = parser.parse_args()
    _parse_changelog('2.18', 'development')
    _parse_changelog('2.16', 'mbedtls-2.16')
    _parse_changelog('2.7', 'mbedtls-2.7')
    combo = _combine_changelog()
    _dump_changelog(combo)


if __name__ == "__main__":
    run_main()
