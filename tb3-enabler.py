#!/usr/bin/env python

# Modified based on Loic Nageleisen's trim_patcher
# https://github.com/lloeki/trim_patcher/

from __future__ import print_function
import os
import sys
import re
import hashlib
import shutil
from subprocess import Popen, PIPE
import shlex

ORIGINAL = 'original'
PATCHED = 'patched'

target = ("/System/Library/Extensions/IOThunderboltFamily.kext/"
          "Contents/MacOS/IOThunderboltFamily")
backup = "%s.original" % target

md5_version = {
    "00e2f0eb5db157462a83e4de50583e33": ["10.12.1 (16B2659)"],
    "ebde660af1f51dc7482551e8d07c62fd": ["10.12.2 (16C67)"],
    "7fbc510cf91676739d638e1319d44e0e": ["10.12.3 (16D32)"],
    "33ff6f5326eba100d4e7c490f9bbf91e": ["10.12.4 (16E195)"],
    "58703942f8d4e5d499673c42cab0c923": ["10.12.5 (16F73)"],
    "8ef3cf6dd8528976717e239aa8b20129": ["10.12.6 (16G29)"],
    "9d6788e5afe3369cac79546a66f34842": ["10.12.6 (16G1036)"],
    "096de0ab3c312a2e432e056d398a096b": ["10.12.6 (16G1114)"],
    "cb95148ca3508790d6bdad38da79c649": ["10.12.6 (16G1212)"],
    "b58ba765f901b3b6f2fac39c2040e523": ["10.13.0 (17A365)"],
    "bcb319c05541da0ccffd7a52da7236c5": ["10.13.1 (17B48)"],
    "427b87e16e15c55c687a565fbd555e03": ["10.13.2 (17C88)"],
    "a47a724fdb13df4cef1b662b7ccbc9d1": ["10.13.3 (17D47)"]
}
md5_patch = {
    "00e2f0eb5db157462a83e4de50583e33": "a6c2143c2f085c2c104369d7a1adfe03",
    "ebde660af1f51dc7482551e8d07c62fd": "2ebb68137da4a1cb0dfc6e6f05be3db2",
    "7fbc510cf91676739d638e1319d44e0e": "0af475c26cdf5e26f8fd7e4341dadea5",
    "33ff6f5326eba100d4e7c490f9bbf91e": "9237f013ab92f7eb5913bd142abf5fae",
    "58703942f8d4e5d499673c42cab0c923": "86c40c5b6cadcfe56f7a7a1e1d554dc9",
    "8ef3cf6dd8528976717e239aa8b20129": "bc84c36d884178d6e743cd11a8a22e93",
    "9d6788e5afe3369cac79546a66f34842": "f1b280854306616dafb54b679c13e58e",
    "096de0ab3c312a2e432e056d398a096b": "52f6d17ef3fb3a0a899c0ea6a255afc9  ",
    "cb95148ca3508790d6bdad38da79c649": "f685774227156630f26a7448c886151b",
    "b58ba765f901b3b6f2fac39c2040e523": "06a1a1fedc294b1bb78bc92625e412e1",
    "bcb319c05541da0ccffd7a52da7236c5": "d0ae8daed7faccb8107f7b17772163b8",
    "427b87e16e15c55c687a565fbd555e03": "d5c12e6f04d87d5b5a8ceef42cd36531",
    "a47a724fdb13df4cef1b662b7ccbc9d1": "bcf9f00b8028bd305176816563ab2c00"
}
md5_patch_r = dict((v, k) for k, v in md5_patch.items())

re_index = [
    {
        'search': "\x55\x48\x89\xE5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xEC\x38\x01",
        'replace': "\x55\x48\x89\xE5\x31\xC0\x5D\xC3\x41\x55\x41\x54\x53\x48\x81\xEC\x38\x01"
    },
    {
        'search': "\x55\x48\x89\xE5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xEC\x28\x01",
        'replace': "\x55\x48\x89\xE5\x31\xC0\x5D\xC3\x41\x55\x41\x54\x53\x48\x81\xEC\x28\x01"
    }
]
re_md5 = {
    0: [
        "00e2f0eb5db157462a83e4de50583e33",
        "ebde660af1f51dc7482551e8d07c62fd",
        "7fbc510cf91676739d638e1319d44e0e",
        "33ff6f5326eba100d4e7c490f9bbf91e",
        "58703942f8d4e5d499673c42cab0c923",
        "8ef3cf6dd8528976717e239aa8b20129",
        "9d6788e5afe3369cac79546a66f34842",
        "096de0ab3c312a2e432e056d398a096b",
        "cb95148ca3508790d6bdad38da79c649"
        ],
    1: [
        "b58ba765f901b3b6f2fac39c2040e523",
        "bcb319c05541da0ccffd7a52da7236c5",
        "427b87e16e15c55c687a565fbd555e03",
        "a47a724fdb13df4cef1b662b7ccbc9d1"
        ]
}
md5_re = dict((v, re_index[k]) for k, l in re_md5.items() for v in l)


def md5(filename):
    h = hashlib.md5()
    with open(filename, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def backquote(command):
    return Popen(shlex.split(command), stdout=PIPE).communicate()[0]

def check_SIP():
    sip_info = backquote("nvram csr-active-config")
    if sip_info.find("%00%00%00") == -1:
        print("you must disable System Integrity Protection",file=sys.stderr)
        sys.exit(1)

def check_rootness():
    if os.geteuid() != 0:
        print("you must be root",file=sys.stderr)
        sys.exit(1)


def clear_kext_cache():
    print( "clearing kext cache...",end="")
    backquote("kextcache -system-prelinked-kernel")
    backquote("kextcache -system-caches")
    print("done")


class UnknownFile(Exception):
    def __init__(self, md5=None):
        self.md5 = md5


class NoBackup(Exception):
    pass


def target_status():
    h = md5(target)
    try:
        return (ORIGINAL, md5_version[h])
    except KeyError:
        pass
    try:
        return (PATCHED, md5_version[md5_patch_r[h]])
    except KeyError:
        pass
    raise UnknownFile(h)


def backup_status():
    if not os.path.exists(backup):
        raise NoBackup
    h = md5(backup)
    try:
        return (ORIGINAL, md5_version[h])
    except KeyError:
        pass
    try:
        return (PATCHED, md5_version[md5_patch_r[h]])
    except KeyError:
        pass
    raise UnknownFile(h)


def apply_patch():
    h = md5(target)
    search_re = md5_re[h]['search']
    replace_re = md5_re[h]['replace']
    with open(target, 'rb') as f:
        source_data = f.read()
    patched_data = source_data.replace(search_re, replace_re)
    with open(target, 'wb') as out:
        out.write(patched_data)


def perform_backup():
    shutil.copyfile(target, backup)

def do_backup():
    check_rootness()
    check_SIP()
    try:
        s, t = target_status()
        if s == PATCHED:
            print("already patched, won't backup")
            sys.exit(1)
        else:
            try:
                _, v = backup_status()
            except NoBackup:
                print( "backing up...",end="")
                perform_backup()
                print( "done")
            else:
                if v == t:
                    print("backup found")
                else:
                    print("backing up...",end="")
                    perform_backup()
                    print("done")
    except UnknownFile as e:
        print( "unknown file, won't backup (md5=%s)" % e.md5)
        sys.exit(1)


def do_restore():
    check_rootness()
    check_SIP()
    print("restoring...",end="")
    backup_status()
    shutil.copyfile(backup, target)
    print("done")
    clear_kext_cache()


def do_apply():
    check_rootness()
    check_SIP()
    do_backup()
    try:
        s, v = target_status()
        if s == PATCHED:
            print("already patched")
            sys.exit()
    except UnknownFile as e:
        print("unknown file: won't patch (md5=%s)" % e.md5)
        sys.exit(1)

    print("patching...",end="")
    apply_patch()

    try:
        s, v = target_status()
        if s != PATCHED:
            print("no change made")
        else:
            print("done")
            clear_kext_cache()
    except UnknownFile as e:
        print("failed (md5=%s), " % e.md5,end="")
        do_restore()

def do_force_apply():
    check_rootness()
    check_SIP()
    if os.path.exists(backup):
        print("backup already exists. won't patch. Please remove the backup from %s and try again." % backup, end="")
        sys.exit(1)
    h = md5(target)
    print("original md5=%s " % h, end="")
    perform_backup()
    with open(target, 'rb') as f:
        source_data = f.read()

    search_re1012 =  "\x55\x48\x89\xE5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xEC\x38\x01"
    replace_re1012 = "\x55\x48\x89\xE5\x31\xC0\x5D\xC3\x41\x55\x41\x54\x53\x48\x81\xEC\x38\x01"

    search_re1013 =  "\x55\x48\x89\xE5\x41\x57\x41\x56\x41\x55\x41\x54\x53\x48\x81\xEC\x28\x01"
    replace_re1013 = "\x55\x48\x89\xE5\x31\xC0\x5D\xC3\x41\x55\x41\x54\x53\x48\x81\xEC\x28\x01"

    for replace in [replace_re1012, replace_re1013]:
        if (source_data.find(replace) != -1):
            print ("Looks like file is already patched, aborting")
            sys.exit(1)

    if (source_data.find(search_re1012) != -1):
        patched_data = source_data.replace(search_re1012, replace_re1012)
    else:
        print ("Could not location to  patch for 10.12, trying for 10.13")
        if (source_data.find(search_re1013) != -1):
            patched_data = source_data.replace(search_re1013, replace_re1013)
        else:
            print ("10.13 also not found, exiting")
            sys.exit(1)

    with open(target, 'wb') as out:
        out.write(patched_data)
    h = md5(target)
    print("done, patched md5=%s" % h, end="")
    clear_kext_cache()

def do_status():
    try:
        print("target:",end="")
        s, v = target_status()
        print( s+',', ' or '.join(v))
    except UnknownFile as e:
        print( "unknown (md5=%s)" % e.md5)

    try:
        print("backup:",end="")
        s, v = backup_status()
        print( s+',', ' or '.join(v))
    except NoBackup:
        print( "none")
    except UnknownFile as e:
        print( "unknown (md5=%s)" % e.md5)


def do_diff():
    try:
        backup_status()
    except NoBackup:
        print("no backup")
    else:
        command = ("bash -c "
                   "'diff <(xxd \"%s\") <(xxd \"%s\")'" % (backup, target))
        print(os.system(command))


commands = {
    'status': do_status,
    'backup': do_backup,
    'apply': do_apply,
    'restore': do_restore,
    'diff': do_diff,
    'forceApply': do_force_apply,
}

try:
    function = commands[sys.argv[1]]
    function()
except IndexError:
    print("no command provided",file=sys.stderr)
    print("list of commands: %s" % ', '.join(commands.keys()),file=sys.stderr)
    sys.exit(1)
except KeyError:
    print ("unknown command",file=sys.stderr)
    sys.exit(1)
