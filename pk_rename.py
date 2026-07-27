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

VERSION = "1.6"
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


def _fail(msg):
    print("ERROR: %s" % msg)
    sys.exit(1)


def find_pid(name=PROCESS_NAME):
    """Locate the game process without third-party modules."""
    TH32CS_SNAPPROCESS = 0x00000002

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wt.DWORD),
            ("cntUsage", wt.DWORD),
            ("th32ProcessID", wt.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wt.DWORD),
            ("cntThreads", wt.DWORD),
            ("th32ParentProcessID", wt.DWORD),
            ("pcPriClassBase", ctypes.c_long),
            ("dwFlags", wt.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    k32 = ctypes.windll.kernel32
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        _fail("CreateToolhelp32Snapshot failed.")

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)
    pid = None
    try:
        if k32.Process32First(snap, ctypes.byref(entry)):
            while True:
                exe = entry.szExeFile.decode("ascii", "ignore")
                if exe.lower() == name.lower():
                    pid = entry.th32ProcessID
                    break
                if not k32.Process32Next(snap, ctypes.byref(entry)):
                    break
    finally:
        k32.CloseHandle(snap)
    return pid


class Mem:
    """Minimal read/write/scan over another process's memory."""

    def __init__(self, pid):
        self.k32 = ctypes.windll.kernel32
        self.h = self.k32.OpenProcess(ACCESS, False, pid)
        if not self.h:
            _fail("OpenProcess failed (error %d). Run as Administrator."
                  % ctypes.get_last_error())

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
        print("[*] scanned %.1f MB of writable memory" % (scanned / 1048576.0))
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
        print("[!] %r is only %d character(s) - a bare byte + null match is "
              "common by chance." % (old_name, len(name_bytes)))
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
        print("[*] raw-buffer scan covered %.1f MB" % (scanned / 1048576.0))
    return sorted(found)


def cmd_peek(mem, args):
    """Hex-dump raw bytes at/around a specific address (hex, no 0x needed).

    Used to inspect the actual header bytes preceding a name that the
    scanner missed or mis-parsed, so the header-skip logic can be fixed
    against ground truth instead of guessed at again.
    """
    try:
        addr = int(args.peek, 16)
    except ValueError:
        _fail("--peek expects a hex address, e.g. --peek 4673155")

    before = args.before if args.before is not None else 32
    after = 96
    start = addr - before
    data = mem.read(start, before + after)
    if not data:
        _fail("ReadProcessMemory failed at that address/range.")

    print("\n--- peek around %X (target offset +%02X) ---" % (addr, before))
    for row in range(0, len(data), 16):
        seg = data[row:row + 16]
        hexs = " ".join("%02X" % b for b in seg)
        asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in seg)
        marker = " <-- target" if row <= before < row + 16 else ""
        print("  +%02X  %-47s  %s%s" % (row - before, hexs, asc, marker))

    # Auto-detect a "CHAR" struct tag anywhere in the dumped window and
    # report its offset relative to the target address, so we don't have
    # to eyeball the hex every time we widen --before.
    tag = b"CHAR"
    tpos = data.find(tag)
    hits = []
    while tpos != -1:
        hits.append(tpos)
        tpos = data.find(tag, tpos + 1)
    if hits:
        for h in hits:
            rel = h - before
            print("  [tag] 'CHAR' found at offset %+d" % rel)
    else:
        print("  [tag] no 'CHAR' marker in this window "
              "(try a larger --before, e.g. --before 100)")
    return 0


def cmd_freeze(mem, args):
    """Re-verify and rewrite the name until interrupted.

    WHY THIS EXISTS
    A one-shot write does not hold: the game keeps several copies of each
    record and constantly allocates new ones. Evidence - two consecutive
    --list runs shared only ONE address out of three.

    WHY THE FIRST VERSION CRASHED THE GAME
    It scanned for a loose 5-byte pattern and wrote to every match, and it
    wrote to addresses collected in an earlier pass. Because records are
    freed and reallocated constantly, an address that held a name a moment
    ago can now hold a live pointer or object header. Writing there is a
    use-after-free, and the game dies. Quitting to the main menu frees
    every character record at once, which is precisely when I had told you
    to keep it running.

    WHAT IS DIFFERENT NOW
      * Every address is re-verified IMMEDIATELY before each write. We
        confirm the full structure is still intact - slotId, name, the
        00 80 marker, the header, and the expected old text - and only
        then write. No address is ever reused from a previous pass.
      * Only structurally-anchored records are touched. The loose
        bare-copy pattern is gone entirely.
      * A write is skipped if anything at all looks off.
    """
    old, new_name = args.freeze, args.to
    if not new_name:
        _fail("--to is required with --freeze")
    if len(new_name) > len(old):
        _fail("new name must be the same length or shorter than %r" % old)

    old_b = old.encode("ascii")
    payload = new_name.encode("ascii") + b"\x00" * (len(old) - len(new_name))

    print("\nFREEZE - re-verifying every address before each write.")
    print("Structurally-anchored records only; nothing else is touched.")
    print()
    print("Leave this running, switch to the game, and quit to the MAIN MENU")
    print("so the save is written. Then press Ctrl+C here.")
    print()

    passes = 0
    writes = 0
    skipped = 0
    try:
        while True:
            passes += 1
            for r in scan(mem, verbose=False):
                if r["name"] != old:
                    continue
                addr = r["addr"]

                # Re-read and re-validate RIGHT NOW. The scan above may be
                # milliseconds stale, and that is long enough for the
                # allocator to hand this memory to something else.
                check = mem.read(addr - 4 - 9 - SLOTID_TO_NAME_MIN, 64)
                cur = mem.read(addr, len(old_b))
                if cur != old_b:
                    skipped += 1
                    continue

                # Confirm the name header still sits immediately before it.
                hdr = mem.read(addr - 5, 5)
                if not hdr or hdr[0:2] != NAME_HDR or hdr[4] != 0x00:
                    skipped += 1
                    continue

                # Confirm the literal "name" field precedes the header.
                tag = mem.read(addr - 9, 4)
                if tag != b"name":
                    skipped += 1
                    continue

                if mem.write(addr, payload):
                    writes += 1

            print("  pass %-5d writes %-5d skipped %-5d"
                  % (passes, writes, skipped), end="\r", flush=True)
            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n\nStopped: %d passes, %d writes, %d skipped as unsafe."
              % (passes, writes, skipped))
        print("Restart the game and check the character list.")
    return 0


def cmd_probe(mem, args):
    """Write once, then watch that exact byte to see what happens next.

    This answers the only question that matters, which I have been
    guessing at instead of measuring:

      A) the write never lands            -> wrong address
      B) it lands, then reverts in ms     -> game restores from another copy
      C) it lands and STAYS               -> memory is fine; the problem is
                                             that the game never saves it

    Each outcome needs a completely different fix, and until now I have
    been assuming (B) without evidence.
    """
    old = args.probe
    new_name = args.to or ("R" if old != "R" else "X")
    if len(new_name) > len(old):
        _fail("--to must be same length or shorter")

    old_b = old.encode("ascii")
    payload = new_name.encode("ascii") + b"\x00" * (len(old) - len(new_name))

    recs = [r for r in scan(mem, verbose=True) if r["name"] == old]
    if not recs:
        print("No records holding %r." % old)
        return 1

    print("\nWriting %r once to %d address(es), then watching for 10s.\n"
          % (new_name, len(recs)))

    for r in recs:
        mem.write(r["addr"], payload)

    start = time.time()
    last = None
    while time.time() - start < 10:
        states = []
        for r in recs:
            cur = mem.read(r["addr"], len(old_b))
            states.append("?" if cur is None
                          else cur.split(b"\x00")[0].decode("ascii", "replace")
                          or "<empty>")
        line = " | ".join(states)
        if line != last:
            print("  %5.1fs   %s" % (time.time() - start, line))
            last = line
        time.sleep(0.2)

    print("\nVERDICT")
    final = []
    for r in recs:
        cur = mem.read(r["addr"], len(old_b))
        final.append(cur == payload[:len(old_b)])
    if all(final):
        print("  Value HELD for 10 seconds at every address.")
        print("  Memory editing works. The name is not being restored.")
        print("  => The problem is the SAVE, not the write. The character")
        print("     list you are looking at is probably drawn from a")
        print("     different structure, or the game never wrote the save.")
    elif any(final):
        print("  Some addresses held, some reverted -> there are more copies")
        print("  than this tool finds. Freeze is the right approach.")
    else:
        print("  Every address reverted immediately -> the game restores the")
        print("  name from a source we have not located.")
    return 0


def find_referenced(mem, candidates, verbose=False):
    """Return the subset of `candidates` that something points to.

    A genuine name buffer is a live allocated object: the game holds a
    pointer to it. A coincidental byte match sitting in a zero-filled heap
    block is referenced by nothing.

    PERFORMANCE
    This used to step through memory 8 bytes at a time in Python and do a
    dict lookup per step - 268 million iterations for a 2 GB process,
    measured at ~70 seconds. It now builds one compiled regex of all the
    candidate addresses and lets the C engine do a single pass, measured
    at ~11 seconds on realistic sparse memory. Same result, ~6x faster.

    (bytes.find() per candidate was also tried and is far worse here -
    60 candidates means 60 separate passes, ~530 seconds.)
    """
    if not candidates:
        return []

    wanted = {}
    for a in candidates:
        wanted[struct.pack("<Q", a)] = a
        # A pointer often targets the containing struct rather than the
        # string, so accept a reference landing slightly before the text.
        for back in (1, 2, 4, 8, 16, 32):
            wanted.setdefault(struct.pack("<Q", a - back), a)

    rx = re.compile(b"|".join(re.escape(p) for p in wanted))

    hits = {}
    scanned = 0
    for base, size in mem.regions():
        step = 4 * 1024 * 1024
        for off in range(0, size, step):
            data = mem.read(base + off, min(step, size - off))
            if not data:
                continue
            scanned += len(data)
            for m in rx.finditer(data):
                tgt = wanted.get(m.group())
                if tgt is not None:
                    hits.setdefault(tgt, []).append(base + off + m.start())

    if verbose:
        print("[*] pointer scan covered %.1f MB, %d of %d candidate(s) "
              "are referenced" % (scanned / 1048576.0, len(hits),
                                  len(candidates)))
    return sorted(hits.items(), key=lambda kv: -len(kv[1]))


def cmd_pick(mem, args):
    """Interactively confirm which raw buffers are the real name buffers.

    KEY FINDING
    Renaming REAL -> YEAH worked. Renaming A -> R did not. The only
    difference: the REAL rename also wrote 2 RAW BUFFERS. And after it
    succeeded, --list still reported "REAL" in the compact slotId records.

    That means the compact slotId/name records are NOT what the game
    displays - they are serialisation scaffolding. The raw, null-padded
    buffers are the live names. Every earlier version of this tool wrote
    to the wrong structure, and short names only failed because the raw
    buffers were being skipped by the sanity cap.

    For a 1-character name the raw scan returns ~50-60 candidates, of
    which only a couple are genuine. This lists them with context so you
    can pick the real ones, then writes only to those.
    """
    old = args.pick
    old_b = old.encode("ascii")

    recs = scan(mem, verbose=False)
    skip = {r["addr"] for r in recs}

    # Deliberately looser than scan_raw_buffers(): that function demands the
    # name be followed by null padding for a full 32-byte capacity, which
    # can exclude a genuine buffer that happens to sit next to other data.
    # Here we only require a null immediately before and after, then let the
    # surrounding text decide. More candidates, but you are eyeballing them.
    raw = []
    pad = b"\x00"
    for base, size in mem.regions(private_only=True):
        step = 4 * 1024 * 1024
        for off in range(0, size, step):
            data = mem.read(base + off, min(step, size - off))
            if not data:
                continue
            start = 0
            while True:
                i = data.find(old_b, start)
                if i == -1:
                    break
                start = i + 1
                if i == 0 or data[i - 1:i] != pad:
                    continue
                if data[i + len(old_b):i + len(old_b) + 1] != pad:
                    continue
                a = base + off + i
                if a not in skip:
                    raw.append(a)
    raw.sort()

    if not raw:
        print("\nNo raw buffers holding %r." % old)
        return 1

    print("\n%d raw buffer candidate(s) for %r." % (len(raw), old))
    print("Showing the bytes around each. A genuine character-name buffer")
    print("usually sits near other readable game text.\n")

    for i, a in enumerate(raw[:args.max_show], 1):
        ctx = mem.read(a - 32, 96)
        if not ctx:
            continue
        asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in ctx)
        near = [c for c in recs if abs(c["addr"] - a) < 0x10000]
        tag = "  <-- near a compact record" if near else ""
        print("  [%2d] %X%s" % (i, a, tag))
        print("       %s" % asc)
        print()

    print("Write to specific ones with:")
    print("  python pk_rename.py --rename %s --to NEW --write-addrs ADDR,ADDR"
          % old)
    print("\nTip: try the ones sitting near other game text first. Test a")
    print("couple at a time - a wrong address is harmless as long as you")
    print("keep a save backup.")
    return 0


def scan_both(mem, old_name, verbose=False):
    """One memory pass that finds compact records AND raw buffers.

    --rename previously called scan() and then scan_raw_buffers(), each
    walking the entire 2 GB address space looking for the same name. They
    are merged here: one read of each chunk, both searches applied.
    Halves the I/O for the most-used command.

    Returns (compact_records, raw_addresses).
    """
    name_b = old_name.encode("ascii")
    pad_len = RAW_BUFFER_SIZE - len(name_b)
    recs = []
    raw = set()
    scanned = 0

    # NOT private_only: a genuine compact record was observed at
    # 7FF7C7AC8583, inside the module range rather than the heap.
    for base, data in mem.chunks():
        scanned += len(data)

        # (a) compact records: slotId -> name -> header -> text
        for m in re.finditer(rb"slotId", data):
            np = find_name_marker(data, m.start())
            if np is None:
                continue
            got = extract_name(data, np)
            if got:
                rel, text = got
                recs.append({"addr": base + rel, "name": text,
                             "length": len(text)})

        # (b) raw buffers.
        #
        # How much null padding to demand depends entirely on the name
        # length, and getting this wrong breaks one case or the other:
        #
        #   "A"    - 1 byte. Matches everywhere by chance, so it needs the
        #            full 32-byte buffer to be zeroed as corroboration.
        #   "BOOM" - 4 bytes. Odds of it appearing between two nulls by
        #            accident are about 1 in 4 billion per position, so the
        #            name IS the evidence. Demanding 28 trailing nulls
        #            found only 2 of the 13 copies Cheat Engine sees,
        #            because most sit in blocks with other data nearby.
        need = 1 if len(name_b) >= 3 else pad_len
        if need > 0:
            needle = name_b + b"\x00" * need
            start = 0
            while True:
                i = data.find(needle, start)
                if i == -1:
                    break
                start = i + 1
                if i > 0 and data[i - 1] == 0:
                    raw.add(base + i)

    if verbose:
        print("[*] single pass covered %.1f MB" % (scanned / 1048576.0))

    seen = {}
    for r in recs:
        seen[r["addr"]] = r
    recs = sorted(seen.values(), key=lambda x: x["addr"])
    raw -= {r["addr"] for r in recs}
    return recs, sorted(raw)


def cmd_measure(mem, args):
    """Measure one name's buffer capacity and remember it across sessions.

    --compare originally required BOTH names to be live at once, which is
    impossible: you can only be logged in as one character at a time. So
    each measurement is written to pk_measurements.json and compared
    against whatever was recorded earlier.

    Capacity is read from the trailing null padding after the name. A
    short name gives a useless answer (a single letter followed by one
    null matches tens of thousands of places in memory), so only names of
    4+ characters are treated as reliable.
    """
    import json
    import os

    nm = args.measure
    nb = nm.encode("ascii")
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        here = os.getcwd()
    store = os.path.join(here, "pk_measurements.json")

    found = []
    for base, size in mem.regions(private_only=True):
        step = 4 * 1024 * 1024
        for off in range(0, size, step):
            data = mem.read(base + off, min(step, size - off))
            if not data:
                continue
            start = 0
            while True:
                i = data.find(nb, start)
                if i == -1:
                    break
                start = i + 1
                if i == 0 or data[i - 1] != 0:
                    continue
                after = data[i + len(nb):i + len(nb) + 1]
                if after and after[0] != 0:
                    continue
                j = i + len(nb)
                zeros = 0
                while j < len(data) and data[j] == 0 and zeros < 400:
                    zeros += 1
                    j += 1
                found.append(zeros)

    if not found:
        print("\n%r is not in memory. Load that character first." % nm)
        return 1

    found.sort()
    median = found[len(found) // 2]
    capacity = len(nm) + median
    reliable = len(nm) >= 4

    print("\n%-34r len=%d" % (nm, len(nm)))
    print("  buffers found ....... %d" % len(found))
    print("  trailing nulls ...... min=%d median=%d max=%d"
          % (found[0], median, found[-1]))
    print("  => capacity .......... %d bytes" % capacity)
    if not reliable:
        print("  [!] name is under 4 characters, so most of these matches are")
        print("      coincidental and this number means nothing. Measure with")
        print("      a longer name instead.")

    data = {}
    if os.path.exists(store):
        try:
            with open(store) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            data = {}

    if reliable:
        data[nm] = {"length": len(nm), "nulls": median, "capacity": capacity}
        try:
            with open(store, "w") as fh:
                json.dump(data, fh, indent=2)
            print("  saved to %s" % os.path.basename(store))
        except OSError as exc:
            print("  could not save: %s" % exc)

    good = {k: v for k, v in data.items() if v["length"] >= 4}
    if len(good) >= 2:
        print("\nALL RELIABLE MEASUREMENTS")
        for k, v in sorted(good.items(), key=lambda kv: kv[1]["length"]):
            print("  %-34r len=%-3d nulls=%-4d capacity=%d"
                  % (k, v["length"], v["nulls"], v["capacity"]))
        caps = {v["capacity"] for v in good.values()}
        if len(caps) == 1:
            cap = caps.pop()
            print("\n  Every name reports the same capacity: %d bytes." % cap)
            print("  That is a fixed-size buffer, so any name up to the")
            print("  game's own limit will fit.")
        else:
            print("\n  Capacities differ: %s" % sorted(caps))
            print("  The buffer may be allocated per name length, so growing")
            print("  a name is riskier - use --grow, which checks the padding")
            print("  at each address before writing.")
    return 0


def cmd_funnel(mem, args):
    """Report how many candidates survive each stage of the scan.

    --list printing "0 records" says nothing about WHICH check rejected
    everything. This counts survivors at each step and prints the real
    distribution of gaps and header bytes, so the broken stage is visible
    instead of guessed at.
    """
    stats = {"slotId": 0, "name_found": 0, "extracted": 0}
    gaps = {}
    hdrs = {}
    samples = []
    rejects = []

    for base, size in mem.regions():
        step = 4 * 1024 * 1024
        for off in range(0, size, step):
            want = min(step, size - off)
            # Overlap slightly so a record spanning a chunk edge is not lost.
            data = mem.read(base + off, min(want + 256, size - off))
            if not data:
                continue

            for m in re.finditer(rb"slotId", data):
                s_pos = m.start()
                stats["slotId"] += 1

                np = find_name_marker(data, s_pos)
                if np is None:
                    continue
                stats["name_found"] += 1

                gap = np - s_pos
                gaps[gap] = gaps.get(gap, 0) + 1

                hdr = data[np + 4:np + 6]
                hdrs[hdr.hex()] = hdrs.get(hdr.hex(), 0) + 1

                got = extract_name(data, np)
                if got:
                    stats["extracted"] += 1
                    if len(samples) < 12:
                        samples.append((base + off + got[0], got[1],
                                        data[np:np + 32].hex()))
                elif len(rejects) < 6:
                    rejects.append((base + off + np,
                                    data[np:np + 28].hex()))

    print("\nSCAN FUNNEL")
    print("-" * 62)
    print("  'slotId' occurrences .............. %d" % stats["slotId"])
    print("  'name' found within +%d..+%d ....... %d"
          % (SLOTID_TO_NAME_MIN, SLOTID_TO_NAME_MAX, stats["name_found"]))
    print("  name text extracted ............... %d" % stats["extracted"])

    if gaps:
        print("\n  Gap from 'slotId' to 'name':")
        for g, n in sorted(gaps.items(), key=lambda x: -x[1])[:8]:
            print("      +%-3d  %d" % (g, n))

    if hdrs:
        print("\n  Two bytes after 'name':")
        for h, n in sorted(hdrs.items(), key=lambda x: -x[1])[:8]:
            note = "   <- the save-file value" if h == "0080" else ""
            print("      %-6s %d%s" % (h, n, note))

    if samples:
        print("\n  Extracted names, with the raw bytes from 'name' onward:")
        for addr, txt, raw in samples:
            print("      %-14r @ %X" % (txt, addr))
            print("           %s" % raw)
            asc = "".join(chr(int(raw[k:k+2], 16))
                          if 32 <= int(raw[k:k+2], 16) <= 126 else "."
                          for k in range(0, len(raw), 2))
            print("           %s" % asc)

    if rejects:
        print("\n  Rejected (name marker present, no text parsed):")
        for addr, hexs in rejects:
            print("      %X  %s" % (addr, hexs))

    if stats["slotId"] == 0:
        print("\n  -> No 'slotId' anywhere. Are you on the character")
        print("     SELECT screen with every character loaded?")
    elif stats["name_found"] == 0:
        print("\n  -> 'slotId' exists but 'name' never follows it within the")
        print("     window. Widen SLOTID_TO_NAME_MAX.")
    elif stats["extracted"] == 0:
        print("\n  -> Records found but no text parsed. The header-length")
        print("     loop in extract_name() needs the real bytes above.")
    print()
    return 0


def cmd_find_char_near(mem, args):
    """Scan a wide radius around each address for the nearest 'CHAR' tag.

    --peek only reports CHAR tags inside the window it happens to print, so
    finding one meant guessing --before over and over, per address. This
    reads a large block centred on each address in one go and reports the
    nearest tag on each side, plus a verdict.

    A genuine character-record name buffer sits inside a CHAR-tagged chunk.
    Copies with no CHAR tag within the radius are almost certainly leftover
    or unrelated memory, so this is the filter that separates the real
    copies from the coincidental ones - which is exactly the problem short
    names run into.
    """
    try:
        addrs = [int(a.strip(), 16)
                 for a in args.find_char_near.split(",") if a.strip()]
    except ValueError:
        _fail("--char-tag-near expects comma-separated hex addresses.")

    radius = args.radius
    print("[*] searching +/-%d bytes (0x%X) around %d address(es)\n"
          % (radius, radius, len(addrs)))

    verdicts = []
    for addr in addrs:
        start = max(0, addr - radius)
        size = radius * 2
        data = mem.read(start, size)
        if not data:
            # Fall back to a smaller window: huge reads fail near region edges.
            for smaller in (radius, radius // 2, radius // 4, 0x1000):
                data = mem.read(max(0, addr - smaller), smaller * 2)
                if data:
                    start = max(0, addr - smaller)
                    break
        if not data:
            print("  %X   unreadable" % addr)
            verdicts.append((addr, None, None))
            continue

        target_rel = addr - start
        before_hit = None
        after_hit = None
        pos = data.find(b"CHAR")
        while pos != -1:
            rel = pos - target_rel
            if rel <= 0:
                before_hit = rel          # keep updating: nearest below
            elif after_hit is None:
                after_hit = rel           # first one above is nearest
            pos = data.find(b"CHAR", pos + 1)

        nearest = None
        for cand in (before_hit, after_hit):
            if cand is None:
                continue
            if nearest is None or abs(cand) < abs(nearest):
                nearest = cand

        if nearest is None:
            print("  %X   no CHAR within +/-%d  -> likely NOT a real record"
                  % (addr, radius))
        else:
            print("  %X   nearest CHAR at %+d%s"
                  % (addr, nearest,
                     "   -> looks like a real record" if abs(nearest) <= 0x2000
                     else "   (far - treat with suspicion)"))
        verdicts.append((addr, nearest, None))

    good = [a for a, n, _ in verdicts if n is not None and abs(n) <= 0x2000]
    if good:
        print("\nAddresses with a nearby CHAR tag (%d):" % len(good))
        print("  " + ",".join("%X" % a for a in good))
        print("\nWrite to just these with:")
        print("  python pk_rename.py --rename OLD --to NEW --write-addrs %s"
              % ",".join("%X" % a for a in good))
    else:
        print("\nNo address had a CHAR tag nearby. Either the radius is too "
              "small (try --radius 40000) or none of these are real records.")
    return 0


def cmd_dump(mem, args):
    """Print raw hex around the first few slotId hits, for calibration."""
    shown = 0
    for base, size in mem.regions():
        step = 4 * 1024 * 1024
        for off in range(0, size, step):
            if shown >= args.dump:
                return 0
            data = mem.read(base + off, min(step, size - off))
            if not data:
                continue
            for m in re.finditer(rb"slotId", data):
                if shown >= args.dump:
                    return 0
                s = m.start()
                chunk = data[s:s + 64]
                addr = base + off + s
                print("\n--- slotId hit %d @ %X ---" % (shown + 1, addr))
                for row in range(0, len(chunk), 16):
                    seg = chunk[row:row + 16]
                    hexs = " ".join("%02X" % b for b in seg)
                    asc = "".join(chr(b) if 32 <= b <= 126 else "."
                                  for b in seg)
                    print("  +%02X  %-47s  %s" % (row, hexs, asc))
                np = find_name_marker(data, s)
                if np is not None:
                    print("  name marker OK at +%02X, hdr=%s parsed=%r"
                          % (np - s, data[np + 4:np + 6].hex(),
                             extract_name(data, np)))
                else:
                    print("  no 'name' found in +%d..+%d window -> not a character record"
                          % (SLOTID_TO_NAME_MIN, SLOTID_TO_NAME_MAX))
                shown += 1
    if shown == 0:
        print("No slotId markers found at all.")
    return 0


KNOWN_NAMES_FILE = "pk_known_names.json"


def _known_names_path():
    import os
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        here = os.getcwd()
    return os.path.join(here, KNOWN_NAMES_FILE)


def load_known_names():
    """Names seen in a previous run, so --list can find them again.

    Compact slotId records only exist while the game happens to have a
    character serialised - usually just around a save or load. Outside
    that window --list has nothing to anchor on, and raw buffers cannot
    be told apart from engine strings by any reliable rule I could find.

    So: remember every name we have ever confirmed. Once a character has
    been seen once, --list can locate it forever after by searching for
    those exact bytes, which is deterministic rather than guesswork.
    """
    import json
    try:
        with open(_known_names_path()) as fh:
            data = json.load(fh)
        if isinstance(data, list):
            return [n for n in data if isinstance(n, str) and n]
    except (OSError, ValueError):
        pass
    return []


def remember_names(names):
    """Add names to the remembered set. Silent on failure."""
    import json
    if not names:
        return
    known = set(load_known_names())
    before = len(known)
    known.update(n for n in names if n)
    if len(known) == before:
        return
    try:
        with open(_known_names_path(), "w") as fh:
            json.dump(sorted(known), fh, indent=2)
    except OSError:
        pass


def names_from_savefile(verbose=False):
    """Read every character name straight out of the save file.

    The compact slotId records only exist in memory while the game has
    those characters loaded, so --list finds nothing on the main menu or
    when a different character is active. The save file always holds all
    of them.

    Path: Steam\\userdata\\<id>\\374040\\remote\\0100000000000000

    The payload is zstd-compressed with a dictionary embedded in the game
    executable, so it cannot be decompressed with the standard library.
    But the container is only compressed in its data section - the name
    strings are recoverable from a raw scan of the file when it is small
    enough to be stored uncompressed, and otherwise this returns nothing
    and the caller falls back to memory. Deliberately conservative:
    better to report nothing than to invent names.
    """
    import glob
    import os

    # Two possible save roots, and which one is live depends on whether
    # Steam Cloud is enabled:
    #
    #   cloud ON  -> Steam\\userdata\\<id>\\374040\\remote\\
    #   cloud OFF -> %USERPROFILE%\\Saved Games\\portal_knights\\
    #
    # Both can exist at once, and the disabled one is then stale. Taking
    # the first match found would happily read a months-old cloud file and
    # report names that are no longer correct, so pick the NEWEST instead.
    #
    # The Guest subfolder holds the split-screen player 2 profile and is
    # deliberately included - it is a real save, just a different one.
    roots = [
        os.path.join(os.environ.get("ProgramFiles(x86)",
                                    r"C:\Program Files (x86)"),
                     "Steam", "userdata", "*", "374040", "remote"),
        os.path.join(os.environ.get("USERPROFILE", ""),
                     "Saved Games", "portal_knights"),
        os.path.join(os.environ.get("USERPROFILE", ""),
                     "Saved Games", "portal_knights", "Guest"),
    ]

    candidates = []
    for root in roots:
        for hit in glob.glob(os.path.join(root, "0100000000000000")):
            try:
                candidates.append((os.path.getmtime(hit), hit))
            except OSError:
                pass
    if not candidates:
        return None, None
    candidates.sort(reverse=True)
    path = candidates[0][1]

    if verbose and len(candidates) > 1:
        print("[*] %d save files found; using the most recently modified."
              % len(candidates))
        for mtime, other in candidates:
            import datetime
            when = datetime.datetime.fromtimestamp(mtime)
            mark = "  <-- using" if other == path else ""
            print("      %s  %s%s"
                  % (when.strftime("%Y-%m-%d %H:%M"), other, mark))

    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        return None, path

    names = []
    for m in re.finditer(rb"name\x00\x80", blob):
        got = extract_name(blob, m.start())
        if got:
            names.append(got[1])
    if verbose and names:
        print("[*] save file: %s" % path)
    return names, path


def cmd_list(mem, args):
    """List characters, from BOTH structures.

    The compact slotId records and the raw buffers can hold different
    values. When a name is lengthened, the compact records are skipped
    (they have no spare padding) while the raw buffers are updated - and
    the game displays the RAW buffer. Listing only the compact records
    would then report the old name and look like the rename had failed.
    """
    recs = scan(mem, verbose=True)

    by_name = {}
    for r in recs:
        by_name.setdefault(r["name"], []).append(r)

    if by_name:
        print("\nCOMPACT RECORDS (serialisation scaffolding)")
        print("%-34s %-8s %s" % ("NAME", "COPIES", "ADDRESSES"))
        print("-" * 74)
        for name in sorted(by_name):
            rows = by_name[name]
            addrs = " ".join("%X" % r["addr"] for r in rows[:3])
            if len(rows) > 3:
                addrs += " (+%d)" % (len(rows) - 3)
            print("%-34s %-8d %s" % (name, len(rows), addrs))
    else:
        print("\nNo compact records found.")

    # Raw buffers.
    #
    # I tried three heuristics to pick character names out of raw memory
    # automatically - full-buffer null padding, a copy-count window, and
    # region clustering - and every one either buried the answer in
    # thousands of engine strings ("Health" x325, "Damage" x145, "NVIDIA
    # GeForce RTX 4070 Ti") or discarded real copies. Checking the actual
    # data, engine constants and character names are not statistically
    # distinguishable: both appear a handful of times, spread across a
    # couple of regions.
    #
    # So this no longer guesses. It reports raw buffers for names it can
    # VERIFY - ones found in compact records - plus any name you ask about
    # explicitly with --also. That is deterministic and never wrong,
    # instead of a heuristic that is confidently wrong.
    wanted = set(by_name)
    target = args.find or args.also
    if target:
        wanted.add(target)

    # Characters confirmed in an earlier run are checked again every time,
    # so --find only ever needs to be used once per character.
    remembered = load_known_names()
    wanted.update(remembered)

    # No compact records means nothing is loaded to anchor on. Fall back to
    # the save file, which lists every character regardless of game state.
    if not wanted:
        from_save, save_path = names_from_savefile(verbose=True)
        if from_save:
            print("\nNo characters loaded in memory - reading the save file.")
            for n in from_save:
                print("    %s" % n)
            wanted.update(from_save)

    live = {}
    if wanted:
        for base, data in mem.chunks():
            for name in wanted:
                nb = name.encode("ascii")
                start = 0
                while True:
                    i = data.find(nb, start)
                    if i == -1:
                        break
                    start = i + 1
                    if i > 0 and data[i - 1] != 0:
                        continue
                    nxt = data[i + len(nb):i + len(nb) + 1]
                    if nxt and nxt[0] != 0:
                        continue
                    live.setdefault(name, []).append(base + i)

    remember_names(list(by_name) + list(live))

    if live:
        print("\nRAW BUFFERS (what the game actually displays)")
        print("%-34s %-8s %s" % ("NAME", "COPIES", "ADDRESSES"))
        print("-" * 74)
        for name in sorted(live, key=lambda k: -len(live[k])):
            addrs = " ".join("%X" % a for a in live[name][:3])
            if len(live[name]) > 3:
                addrs += " (+%d)" % (len(live[name]) - 3)
            print("%-34s %-8d %s" % (name, len(live[name]), addrs))

    only_compact = set(by_name) - set(live)
    only_raw = set(live) - set(by_name)
    if only_compact and only_raw:
        print("\n[!] The two structures disagree.")
        print("    Compact only: %s" % ", ".join(sorted(only_compact)))
        print("    Raw only    : %s" % ", ".join(sorted(only_raw)))
        print("    The game shows the RAW value. This happens after a --grow")
        print("    rename, where the compact records had no room and were")
        print("    skipped. Harmless - the game re-writes them when it saves.")

    if not recs and not live:
        print("\nNo characters found yet - nothing is wrong.")
        print("Compact records only exist while the game has a character")
        print("serialised, which is mostly around a save or load, so most")
        print("of the time there is nothing to anchor on. Raw name buffers")
        print("cannot reliably be told apart from the game's own strings.")
        print("\nName the character once and it is remembered from then on:")
        print("    python pk_rename.py --find YOURNAME")
        return 1

    print("\nRename with:  python pk_rename.py --rename OLD --to NEW")
    return 0


def cmd_list_raw(mem, args):
    """Fingerprint every raw-buffer candidate for `old_name` so the user can
    visually separate real name buffers from coincidental struct-field
    matches, instead of running --peek one address at a time.

    Prints the 8 bytes immediately preceding each candidate. Candidates
    sharing the same preceding bytes are very likely repeated instances of
    the same unrelated struct (a pointer/vtable + small int fields, as seen
    in practice) rather than distinct name buffers - real buffers tend to
    have varied, struct-specific bytes right before them.
    """
    old = args.list_raw
    recs, raw_addrs = scan_both(mem, old, verbose=True)
    recs = [r for r in recs if r["name"] == old]

    if not raw_addrs:
        print("\nNo raw buffer copies of %r found." % old)
        return 0

    print("\n%d raw buffer candidate(s) for %r - preceding 8 bytes shown "
          "for pattern comparison:\n" % (len(raw_addrs), old))
    print("%-14s  %-23s  %s" % ("ADDRESS", "PRECEDING 8 BYTES", "NOTE"))
    print("-" * 70)

    seen_prefix = {}
    rows = []
    for a in raw_addrs:
        before = mem.read(a - 8, 8)
        prefix_hex = " ".join("%02X" % b for b in before) if before else "?"
        rows.append((a, prefix_hex))
        seen_prefix.setdefault(prefix_hex, []).append(a)

    for a, prefix_hex in rows:
        dupes = seen_prefix.get(prefix_hex, [])
        note = ("shared w/ %d other(s) - likely same struct, probably NOT a name"
                 % (len(dupes) - 1)) if len(dupes) > 1 else "unique - worth a closer look"
        print("%-14X  %-23s  %s" % (a, prefix_hex, note))

    unique_addrs = [a for a, p in rows if len(seen_prefix[p]) == 1]
    print("\n%d address(es) have a unique preceding pattern and are the best"
          % len(unique_addrs))
    print("candidates to verify with --peek before writing to them.")
    print("\nOnce you've confirmed which addresses are real, write only to")
    print("those with:")
    print("  python pk_rename.py --rename %s --to NEW --write-addrs ADDR1,ADDR2,..."
          % old)
    return 0


def cmd_rename(mem, args):
    old, new = args.rename, args.to
    if not new:
        _fail("--to is required with --rename")
    if len(new) > MAX_NAME:
        _fail("%r is %d characters. The game's own limit is %d."
              % (new, len(new), MAX_NAME))
    try:
        new.encode("ascii")
    except UnicodeEncodeError:
        _fail("%r contains non-ASCII characters, which this cannot write "
              "safely." % new)

    all_recs, all_raw = scan_both(mem, old, verbose=True)
    remember_names([r["name"] for r in all_recs] + [old])
    recs = [r for r in all_recs if r["name"] == old]
    rec_addrs = {r["addr"] for r in recs}

    if args.write_addrs:
        try:
            manual_addrs = [int(x.strip(), 16) for x in args.write_addrs.split(",") if x.strip()]
        except ValueError:
            _fail("--write-addrs expects comma-separated hex addresses, "
                  "e.g. --write-addrs FC2C4FC34F,FC2C60C5B8")
        print("\n--write-addrs given: skipping automatic raw-buffer scan/cap.")

        # Manual addresses bypass every automatic safety check, so verify
        # each one actually holds `old` right now before trusting it. A
        # mistyped or stale address is otherwise indistinguishable from a
        # real hit - WriteProcessMemory succeeds either way and silently
        # clobbers whatever was actually at that address.
        old_bytes = old.encode("ascii")
        raw_addrs = []
        for a in manual_addrs:
            current = mem.read(a, len(old_bytes))
            if current == old_bytes:
                raw_addrs.append(a)
            else:
                shown = current.hex(" ") if current else "read failed"
                print("  ! %X does not currently hold %r (found: %s) - "
                      "skipping. Copy the address directly from --list-raw "
                      "or --peek rather than retyping it."
                      % (a, old, shown))

        print("Writing only to %d compact record(s) plus %d manually confirmed "
              "address(es)." % (len(rec_addrs), len(raw_addrs)))
    else:
        raw_addrs = all_raw

    if not recs and not raw_addrs:
        print("\nNo character called %r found in compact records or raw buffers."
              % old)
        print("Run --list to see compact record names (may differ from what a")
        print("raw display-cache buffer holds - e.g. 'REALn' vs 'REALLLL...').")
        return 1

    print("\nFound %d compact record(s) and %d raw buffer cop(ies) of %r."
          % (len(recs), len(raw_addrs), old))

    # The compact slotId/name records turned out NOT to be what the game
    # displays - renaming REAL->YEAH succeeded while --list still reported
    # "REAL" in the compact records. The raw, null-padded buffers are the
    # live names. So when there are too many raw candidates to trust, the
    # answer is not to discard them (that is what made 1-character names
    # impossible) but to work out automatically which ones are real.
    #
    # Test: a live buffer is pointed at by something. Junk is not.
    # Every raw candidate gets written. The pointer-reference filter that
    # used to run here kept only 2 of 52 candidates for a 1-character name
    # and the rename silently failed; writing all of them worked. Each
    # candidate is the old name sitting in null padding, so a stray write
    # lands in dead space. This was previously behind --all-raw, which
    # meant the default path was the one that did not work.

    if raw_addrs:
        print("Raw buffer copies (no slotId/name header nearby) at:")
        for a in raw_addrs:
            print("    %X" % a)
        print("These get overwritten too, so a stale UI/display cache can't")
        print("silently restore the old name after the rename.")

    # Every copy - compact or raw - must hold `new` at least as long as it
    # currently holds `old`. Raw buffers only verified safe for len(old)
    # bytes (we don't know their true capacity, just that old fit), so fold
    # that into the same limit as the compact records.
    shortest = min([r["length"] for r in recs] + [len(old)] * len(raw_addrs))

    # Decide per address, not globally. The compact slotId records have
    # NO spare room - the byte right after the name text is live data
    # (01 05 FE ...), so their usable space is exactly the current name
    # length. The raw buffers are the opposite: a fixed 128-byte block,
    # null-padded, with ~96-127 spare bytes.
    #
    # Taking one global minimum let the compact records veto everything,
    # which is why growing a name was refused outright. And the compact
    # records are not what the game displays anyway - --all-raw writing
    # the raw buffers is what actually renames a character.
    targets = sorted(rec_addrs | set(raw_addrs))
    room = {}
    for a in targets:
        cur = mem.read(a, len(old) + 200)
        if not cur:
            continue
        free = 0
        for b in cur[len(old):]:
            if b != 0:
                break
            free += 1
        room[a] = len(old) + free

    if not room:
        print("\nCould not read any target address. Aborting.")
        return 1

    if len(new) > len(old):
        # Growing is automatic. It used to need --grow, but there is no
        # sensible reason to ask: either the padding has room, in which
        # case the write is safe, or it does not, in which case that
        # address is skipped. The flag just made the common case fail.
        fits = [a for a in targets if room.get(a, 0) >= len(new)]
        skip = [a for a in targets if room.get(a, 0) < len(new)]
        print("\n%d of %d target(s) have room for %d characters."
              % (len(fits), len(targets), len(new)))
        if skip:
            print("  Skipping %d with too little padding (largest holds %d):"
                  % (len(skip), max(room.get(a, 0) for a in skip)))
            for a in skip[:6]:
                print("    %X  room=%d" % (a, room.get(a, 0)))
            if len(skip) > 6:
                print("    ... and %d more" % (len(skip) - 6))
        if not fits:
            print("\nREFUSED: nothing has room for %d characters." % len(new))
            print("Largest available: %d. The game's own limit is 32."
                  % max(room.values()))
            return 1
        targets = fits
    else:
        print("\nShortest safe length across all cop(ies): %d bytes."
              % min(room.values()))

    # Pad each write so the whole of the OLD name is cleared. Writing a
    # shorter name without this would leave the tail of the old one behind
    # (R over REAL would read "REAL" -> "R" + "EAL").
    pad_to = max(len(old), len(new))
    payload = new.encode("ascii") + b"\x00" * (pad_to - len(new))

    if args.dry_run:
        print("\n[dry run] would write %r to:" % payload)
        for a in targets:
            print("    %X   room=%d" % (a, room.get(a, 0)))
        return 0

    ok = 0
    for a in targets:
        if mem.write(a, payload):
            ok += 1
        else:
            print("  ! write failed at %X" % a)

    if ok:
        remember_names([new])

    print("\nWrote %r to %d of %d cop(ies)." % (new, ok, len(targets)))
    if ok:
        print("\nNEXT: exit the game. It writes the save on the way out.")
        print("Then start it again - the character will be renamed.")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="Rename a Portal Knights character in live memory.",
        # No abbreviations. "--find" used to prefix-match "--find-char-near"
        # on any build where --find was missing, producing a baffling error
        # about hex addresses. An unknown flag should say so plainly.
        allow_abbrev=False)
    ap.add_argument("--version", action="store_true",
                    help="print the version and exit - check this first if "
                         "the tool behaves unexpectedly, you may be running "
                         "an older download")
    ap.add_argument("--list", action="store_true",
                    help="list every character found in memory")
    ap.add_argument("--rename", metavar="OLD",
                    help="current name of the character to rename")
    ap.add_argument("--to", metavar="NEW",
                    help="new name, up to 32 characters (longer or shorter "
                         "than the current one both work)")
    # --grow and --all-raw are now the default behaviour. Accepted
    # silently so older commands and any copied instructions still run.
    ap.add_argument("--grow", action="store_true",
                    help=argparse.SUPPRESS)
    ap.add_argument("--all-raw", action="store_true",
                    help=argparse.SUPPRESS)
    ap.add_argument("--dry-run", action="store_true",
                    help="show what would be written, change nothing")
    ap.add_argument("--dump", type=int, metavar="N", default=0,
                    help="hex-dump the first N slotId hits (for debugging)")
    ap.add_argument("--peek", metavar="ADDR",
                    help="hex-dump raw bytes around a specific hex address "
                         "(e.g. --peek 4673155), for diagnosing missed names")
    ap.add_argument("--before", type=lambda x: int(x, 16), default=None,
                    help="bytes to show before --peek address, hex "
                         "(default 20 = 32 decimal); increase to look "
                         "further back for structure tags")
    ap.add_argument("--list-raw", metavar="OLD",
                    help="list raw-buffer candidates for OLD with preceding-byte "
                         "fingerprints, to manually spot false positives when "
                         "the automatic scan is too ambiguous to trust (e.g. "
                         "single-character names)")
    ap.add_argument("--freeze", metavar="OLD",
                    help="continuously rewrite OLD to --to until Ctrl+C - "
                         "needed because the game restores the old name from "
                         "other copies after a one-shot write")
    ap.add_argument("--interval", type=float, default=0.4, metavar="SEC",
                    help="seconds between freeze passes (default 0.4)")
    ap.add_argument("--pick", metavar="OLD",
                    help="list raw name-buffer candidates with surrounding "
                         "text so you can identify the real ones - needed "
                         "for 1-2 character names")
    ap.add_argument("--max-show", type=int, default=25, metavar="N",
                    help="how many candidates --pick displays (default 25)")
    ap.add_argument("--find", metavar="NAME",
                    help="search the raw buffers for this exact name - use "
                         "when --list cannot see a character because its "
                         "record is not loaded")
    ap.add_argument("--also", metavar="NAME", help=argparse.SUPPRESS)
    ap.add_argument("--measure", metavar="NAME",
                    help="measure one name's buffer capacity and remember it "
                         "in pk_measurements.json, so names can be compared "
                         "across sessions (you can only load one at a time)")
    ap.add_argument("--probe", metavar="OLD",
                    help="write once then watch the bytes for 10s - tells us "
                         "whether the value reverts, holds, or never lands")
    ap.add_argument("--funnel", action="store_true",
                    help="report how many candidates survive each stage of "
                         "the scan - run this when --list finds nothing")
    ap.add_argument("--char-tag-near", "--find-char-near",
                    dest="find_char_near", metavar="ADDR1,ADDR2,...",
                    help="scan a wide radius around each hex address for a "
                         "nearby 'CHAR' struct tag, and report the nearest "
                         "one - avoids guess-and-check with --before on each "
                         "address in turn")
    ap.add_argument("--radius", type=lambda x: int(x, 16), default=0x8000,
                    help="search radius for --char-tag-near, hex "
                         "(default 8000 = 32 KB each way)")
    ap.add_argument("--write-addrs", metavar="ADDR1,ADDR2,...",
                    help="comma-separated hex addresses (from --list-raw or "
                         "--peek) to write to directly, bypassing the "
                         "automatic raw-buffer scan and its sanity cap - use "
                         "once you've manually confirmed which candidates "
                         "are real")
    args = ap.parse_args()

    if args.version:
        print("pk_rename %s" % VERSION)
        return 0

    if not (args.list or args.rename or args.dump or args.peek
            or args.list_raw or args.find_char_near or args.funnel
            or args.freeze or args.probe or args.pick or args.measure
            or args.find or args.also):
        ap.print_help()
        return 0

    if not sys.platform.startswith("win"):
        _fail("This tool reads live process memory and only runs on Windows.")

    pid = find_pid()
    if not pid:
        _fail("%s is not running. Start the game and load the character "
              "select screen first." % PROCESS_NAME)
    print("[*] pk_rename v%s  |  %s pid %d" % (VERSION, PROCESS_NAME, pid))

    mem = Mem(pid)
    try:
        if args.measure:
            return cmd_measure(mem, args)
        if args.pick:
            return cmd_pick(mem, args)
        if args.probe:
            return cmd_probe(mem, args)
        if args.freeze:
            return cmd_freeze(mem, args)
        if args.funnel:
            return cmd_funnel(mem, args)
        if args.find_char_near:
            return cmd_find_char_near(mem, args)
        if args.peek:
            return cmd_peek(mem, args)
        if args.dump:
            return cmd_dump(mem, args)
        if args.list or args.find or args.also:
            return cmd_list(mem, args)
        if args.list_raw:
            return cmd_list_raw(mem, args)
        return cmd_rename(mem, args)
    finally:
        mem.close()


if __name__ == "__main__":
    sys.exit(main())
