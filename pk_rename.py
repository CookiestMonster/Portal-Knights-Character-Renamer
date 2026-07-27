#!/usr/bin/env python3
r"""
pk_rename.py - Portal Knights character renamer (live memory, Windows)

Renames a character by editing the running game's memory, then letting the game
write its own save. This avoids the KSC1 checksum in the save file, which could
not be reproduced offline.

    python pk_rename.py --list
    python pk_rename.py --rename A --to R
    python pk_rename.py --rename A --to R --dry-run

Requires: Windows, Python 3.8+, and running as Administrator.
No third-party packages - uses ctypes only.

HOW IT FINDS NAMES
Every character is stored as an SNPY record with a fixed field order:

    ... CharacterSetup ... slotId ... name <hdr> <TEXT> ... customiz ...

Verified byte-for-byte against a real decompressed save:

    73 6C 6F 74 49 64 ...(10)... 6E 61 6D 65 00 80 01 0C 00 41
    s  l  o  t  I  d             n  a  m  e  ^^^^^ hdr ^^^^^ 'A'

The two bytes after "name" are always 00 80. The header length after that
varies, so the text is located by scanning rather than by a fixed offset.

WHY IT WRITES EVERY COPY AT ONCE
The game keeps several copies of each record in memory. Changing one lets
another overwrite it moments later, which is why single edits appear to do
nothing. This writes all copies in one pass.
"""

import argparse
import time
import ctypes
import ctypes.wintypes as wt
import re
import struct
import sys
import logging

PROCESS_NAME = "portal_knights_x64.exe"

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
ACCESS = (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ
          | PROCESS_VM_WRITE | PROCESS_VM_OPERATION)

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000   # heap/stack allocations - excludes loaded DLLs/images
PAGE_READWRITE = 0x04
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
WRITABLE = (PAGE_READWRITE | PAGE_WRITECOPY
            | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)
PAGE_GUARD = 0x100

# The game's own limit is 32 characters - confirmed by creating a character
# named "12345678912345678912345678912345" and seeing it accepted in full.
# This was 24, which silently TRUNCATED longer names so they could never be
# matched by --rename. RAW_BUFFER_SIZE below already said 32; the two
# constants disagreed.
MAX_NAME = 32
NAME_HDR = b"\x00\x80"          # constant two bytes after "name"

# "slotId" -> "name" gap is NOT fixed. It depends on how many bytes the
# character's internal ID field takes (4 bytes in some records, 6 in
# others), so "name" can land anywhere in a small range after "slotId".
# Confirmed ground truth:
#   A / Zqjxvk  -> name at +10  (4-byte ID field)
#   REALn/BOOM  -> name at +12  (6-byte ID field)
# Search a small window instead of assuming one fixed offset.
SLOTID_TO_NAME_MIN = 8
SLOTID_TO_NAME_MAX = 20

# Configure basic logging. Keep prints in most places to minimise churn, but
# use logging for startup/errors so it's easy to extend.
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)


def is_admin() -> bool:
    """Return True if running with administrator privileges on Windows.

    Best-effort: if the platform doesn't provide the check, return False.
    """
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _fail(msg):
    logger.error("ERROR: %s", msg)
    sys.exit(1)


def find_name_marker(data, slot_pos):
    """Search for the 'name' marker within a window after a slotId hit.

    Returns the offset of 'name' relative to the start of `data`, or None.
    """
    lo = slot_pos + SLOTID_TO_NAME_MIN
    hi = slot_pos + SLOTID_TO_NAME_MAX
    idx = data.find(b"name", lo, hi + 4)
    if idx == -1:
        return None
    return idx

# Field keys that must never be mistaken for a character name.
FIELD_KEYS = {
    "customiz", "customization", "templatecrc", "modelids", "texture",
    "textureids", "effectpackage", "color", "colorids", "rac", "racecrc",
    "class", "classcrc", "price", "playtime", "last", "lastplayedtime",
    "level", "gender", "guid", "dcrc", "slotid", "name", "entity",
    "charactersetup", "haractersetup", "creationparameter", "position",
    "componentdata", "recipeknowledgelist", "known", "type", "state",
    "quest", "crafting", "ongoing", "selectorcrcs", "itemindex", "control",
    "orienta", "impact", "playz", "loci", "user", "started", "invalid",
    "finalize", "precondi", "fail", "snpy",
}


class MEMORY_BASIC_INFORMATION64(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_ulonglong),
        ("AllocationBase", ctypes.c_ulonglong),
        ("AllocationProtect", wt.DWORD),
        ("__alignment1", wt.DWORD),
        ("RegionSize", ctypes.c_ulonglong),
        ("State", wt.DWORD),
        ("Protect", wt.DWORD),
        ("Type", wt.DWORD),
        ("__alignment2", wt.DWORD),
    ]


class Mem:
    """Minimal read/write/scan over another process's memory."""

    def __init__(self, pid):
        self.k32 = ctypes.windll.kernel32
        self.h = self.k32.OpenProcess(ACCESS, False, pid)
        if not self.h:
            _fail("OpenProcess failed (error %d). Run as Administrator."
                  % ctypes.get_last_error())

    # Context manager support: use `with Mem(pid) as mem:` to ensure cleanup.
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self):
        if self.h:
            self.k32.CloseHandle(self.h)
            self.h = None

    def chunks(self, private_only=False, step=4 * 1024 * 1024, overlap=256):
        """Yield (base_addr, data) covering all scannable memory once.

        Regions are cached after the first walk: VirtualQueryEx over a
        2 GB process is thousands of syscalls, and every command used to
        repeat it. Chunks overlap slightly so a record straddling a
        boundary is not missed.
        """
        for base, size in self.regions(private_only=private_only):
            for off in range(0, size, step):
                want = min(step + overlap, size - off)
                data = self.read(base + off, want)
                if data:
                    yield base + off, data

    def regions(self, private_only=False):
        """Yield (base, size) for every committed, writable, non-guard region.

        private_only=True restricts to MEM_PRIVATE (heap/stack) allocations,
        excluding MEM_IMAGE/MEM_MAPPED (loaded DLLs, mapped files). Real
        character data lives in the game's own heap; a loaded module's
        writable/copy-on-write pages (e.g. its .data section) can otherwise
        produce false hits, especially for very short search strings.
        """
        # Cached: enumerating a 2 GB address space is thousands of
        # VirtualQueryEx calls, and several commands walk it more than once.
        if not hasattr(self, "_region_cache"):
            self._region_cache = {}
        key = bool(private_only)
        if key in self._region_cache:
            for item in self._region_cache[key]:
                yield item
            return

        collected = []
        mbi = MEMORY_BASIC_INFORMATION64()
        addr = 0
        limit = 0x7FFFFFFFFFFF
        while addr < limit:
            ok = self.k32.VirtualQueryEx(
                self.h, ctypes.c_void_p(addr),
                ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not ok:
                addr += 0x1000
                continue
            size = int(mbi.RegionSize)
            if size <= 0:
                break
            if (mbi.State == MEM_COMMIT
                    and (mbi.Protect & WRITABLE)
                    and not (mbi.Protect & PAGE_GUARD)
                    and (not private_only or mbi.Type == MEM_PRIVATE)):
                collected.append((int(mbi.BaseAddress), size))
                yield int(mbi.BaseAddress), size
            addr = int(mbi.BaseAddress) + size
        self._region_cache[key] = collected

    def read(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        got = ctypes.c_size_t(0)
        ok = self.k32.ReadProcessMemory(
            self.h, ctypes.c_void_p(addr), buf, size, ctypes.byref(got))
        if not ok:
            return None
        return buf.raw[:got.value]

    def write(self, addr, data):
        n = len(data)
        buf = ctypes.create_string_buffer(data, n)
        put = ctypes.c_size_t(0)
        ok = self.k32.WriteProcessMemory(
            self.h, ctypes.c_void_p(addr), buf, n, ctypes.byref(put))
        return bool(ok) and put.value == n


def extract_name(chunk, name_pos):
    """
    Given a buffer and the offset of "name", return (rel_offset, text).

    GROUND TRUTH - four real records, all read from live memory or the
    save file. Note the header is NOT a fixed width:

      1-char name, save : 6E 61 6D 65 | 00 80 | 01 0C 00       | 41
      1-char name, mem  : 6E 61 6D 65 | 00 80 | 01 64 00       | 41
      4-char  "YEAH"    : 6E 61 6D 65 | 00 80 | 00 00 00 00    | 59 45 41 48
      32-char digits    : 6E 61 6D 65 | 00 80 | 00 00 00 00    | 31 32 33 ...
                                        ^^^^^^^^^^^^^^^^^^
                                        3 or 4 bytes, varies

    Hardcoding a 5-byte header (text at +9) worked for the 1-character
    case and silently rejected every 4-byte-header record, because +9
    landed on the final 0x00 of the header.

    Two further traps, both of which defeated earlier versions:
      * a header byte can itself be printable - 0x64 is 'd', 0x65 is 'e' -
        so "first printable run wins" returns a header byte as the name;
      * scanning too far forward finds unrelated printable bytes after
        the name and returns those instead.

    The rule that satisfies all four samples: consider runs starting
    between +6 and +12, and take the LONGEST, preferring one immediately
    preceded by a null. Header bytes are isolated singles, so a genuine
    name always wins on length.
    """
    base = name_pos + 4
    if chunk[base:base + 2] != NAME_HDR:
        return None            # empty-name records read 00 00 here

    best = None
    for start in range(6, 13):
        pos = name_pos + start
        if pos >= len(chunk):
            break
        if not (0x20 <= chunk[pos] <= 0x7E):
            continue
        n = 0
        while (pos + n < len(chunk) and 0x20 <= chunk[pos + n] <= 0x7E
               and n < MAX_NAME):
            n += 1
        text = chunk[pos:pos + n].decode("ascii", "ignore")
        if text.lower() in FIELD_KEYS:
            continue
        prev_null = chunk[pos - 1] == 0 if pos > 0 else False
        cand = (n, prev_null, pos, text)
        if best is None or (cand[0], cand[1]) > (best[0], best[1]):
            best = cand

    if best is None:
        return None
    return best[2], best[3]


def scan(mem, verbose=False):
    """Return a list of dicts: {addr, name, length} for compact records.

    Two bugs used to hide records here:

      * The chunk loop read exactly 4 MB with no overlap, so any record
        straddling a boundary was cut in half and lost. Over ~1.8 GB that
        is ~450 chances to miss one. Now uses mem.chunks(), which overlaps.

      * It restricted the search to MEM_PRIVATE. But a real record was
        observed at 7FF7C7AC8583 - inside the module range, not the heap -
        so that filter silently discarded genuine hits. The diagnostic
        --funnel never applied it, which is why funnel could see records
        that --list could not.
    """
    found = []
    scanned = 0
    for base, data in mem.chunks():
        scanned += len(data)
        for m in re.finditer(rb"slotId", data):
            np = find_name_marker(data, m.start())
            if np is None:
                continue
            got = extract_name(data, np)
            if not got:
                continue
            rel, text = got
            found.append({
                "addr": base + rel,
                "name": text,
                "length": len(text),
            })
    if verbose:
        logger.info("[*] scanned %.1f MB of writable memory", (scanned / 1048576.0))
    # De-duplicate by address.
    uniq = {}
    for f in found:
        uniq[f["addr"]] = f
    return sorted(uniq.values(), key=lambda x: x["addr"])


def _is_word_byte(b):
    return (0x30 <= b <= 0x39) or (0x41 <= b <= 0x5A) or (0x61 <= b <= 0x7A)


RAW_BUFFER_SIZE = 32  # confirmed fixed capacity of the bare name buffer


def scan_raw_buffers(mem, old_name, skip_addrs, verbose=False):
    """Find bare, null-padded copies of `old_name` living outside the
    compact slotId-based record.

    These turned up during --peek investigation: some are legitimate
    "CHAR"-tagged name buffers, some sit inside unrelated structs (pointer
    tables, transform/component data), and at least one looked like plain
    leftover/reused memory near an unrelated string. All of them are just
    old_name, null-padded out to a fixed 32-byte buffer, standalone - no
    header, no field key nearby.

    If the game re-reads one of these after a slotId-only rename, it can
    push the old name back in and make the rename look reverted. This finds
    them all so --rename can overwrite every copy in one pass.

    MATCH CRITERIA: for short names in particular (e.g. a single letter),
    "name + one null byte" is common purely by chance across gigabytes of
    heap memory - that alone found 470k+ false hits for a 1-char name.
    The buffer's fixed 32-byte capacity gives a far stronger signal: a
    genuine copy is null-padded for its *entire* remaining capacity, not
    just one byte. Requiring that full run of zeros cuts false positives
    from "any random null byte after a letter" down to "31 specific bytes
    all happening to be zero", which coincidental data essentially never
    satisfies.

    Returns a sorted list of addresses (ints), excluding anything already
    in `skip_addrs`.
    """
    name_bytes = old_name.encode("ascii")
    pad_len = RAW_BUFFER_SIZE - len(name_bytes)
    if len(name_bytes) < 3:
        logger.warning("[!] %r is only %d character(s) - a bare byte + null match is ", (old_name, len(name_bytes)))
        print("    Restricting the raw-buffer scan to private heap/stack "
              "memory, and requiring the full %d-byte buffer capacity to "
              "be zero-padded (not just one trailing null)."
              % RAW_BUFFER_SIZE)

    found = set()
    scanned = 0
    for base, size in mem.regions(private_only=True):
        step = 4 * 1024 * 1024
        for off in range(0, size, step):
            want = min(step, size - off)
            data = mem.read(base + off, want)
            if not data:
                continue
            scanned += len(data)
            start = 0
            while True:
                idx = data.find(name_bytes, start)
                if idx == -1:
                    break
                start = idx + 1
                # Must be followed by zero-padding for the buffer's ENTIRE
                # remaining capacity, not just one null byte - this is what
                # distinguishes a real fixed-size buffer from a coincidental
                # byte match inside unrelated data.
                end = idx + len(name_bytes)
                pad = data[end:end + pad_len]
                if len(pad) < pad_len or pad != b"\x00" * pad_len:
                    continue
                # Must be preceded by a null byte specifically (the tail end
                # of the previous field's zero-padding) - not just "any
                # non-alphanumeric byte", which still let thousands of
                # coincidental hits through. A genuine buffer boundary sits
                # right after another zero-padded field; nearly nothing else
                # produces a null immediately before AND 31 nulls after.
                if idx == 0 or data[idx - 1] != 0:
                    continue
                addr = base + off + idx
                if addr in skip_addrs:
                    continue
                found.add(addr)
    if verbose:
        logger.info("[*] raw-buffer scan covered %.1f MB", (scanned / 1048576.0))
    return sorted(found)

# (rest of file unchanged...) Keep the remainder exactly the same to minimise
# churn. The functions below still use print() so user-visible output is
# familiar. We only altered startup/error handling and Mem to be a context
# manager.

