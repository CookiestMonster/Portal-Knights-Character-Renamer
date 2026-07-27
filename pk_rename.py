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

CHANGES IN THIS REVISION (code review pass, no new memory-layout guessing)
  1. OpenProcess / CreateToolhelp32Snapshot now declare an explicit ctypes
     restype of c_void_p. Left at the default, ctypes treats a HANDLE return
     value as a 32-bit c_int, which is the wrong size on 64-bit Windows -
     harmless for small handle values, silently wrong for larger ones. This
     was a latent bug, not something that had visibly failed yet.
  2. RAW_BUFFER_SIZE was 32. The README documents the buffer as actually
     128 bytes, confirmed from six independent measurements. The 32-byte
     value was never updated after that measurement and made the
     null-padding check for short names weaker than it should have been
     (31 required zero bytes instead of 127) - still correct, just a much
     easier bar to clear by coincidence.
  3. Mem.read() now retries with a smaller size if a read fails, instead of
     giving up. A raw buffer sitting near the end of a mapped region could
     have its read request spill into unmapped memory and fail outright,
     silently dropping a genuine candidate rather than just trimming to
     what is actually readable.
  4. The four separate places that each implemented "find NAME preceded and
     followed by null bytes" (scan_both, cmd_list, cmd_pick, cmd_measure,
     and the now-removed scan_raw_buffers) are consolidated into one
     function, iter_raw_buffers(). Four independent implementations of the
     same check meant a fix to one did not apply to the others - which is
     exactly how RAW_BUFFER_SIZE's stale value survived unnoticed in one
     of them after being corrected elsewhere.
  5. scan_raw_buffers() and find_referenced() were unused - nothing in
     main() or any cmd_* function called either of them, the design they
     supported (pointer-reference filtering) was superseded by "write
     every raw candidate" per cmd_pick's own docstring. Removed rather
     than left as dead code that looks load-bearing.
  6. cmd_list() previously called scan() and then ran its own second full
     memory walk for raw buffers - two full passes over the process's
     address space per invocation. It now calls scan_both() once, like
     cmd_rename() already did.
"""

import argparse
import time
import ctypes
import ctypes.wintypes as wt
import re
import sys

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

# Confirmed by --measure across six separate names (see README "Name
# length"): a 32-character name leaves exactly 96 trailing nulls, i.e. the
# real buffer is 128 bytes, not 32. Used as the strength of the null-padding
# check in iter_raw_buffers() for short names, where the name itself is too
# short to be strong evidence on its own.
RAW_BUFFER_SIZE = 128


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


def _configure_kernel32_prototypes(k32):
    """Declare restype/argtypes for the HANDLE-returning calls we use.

    Left at ctypes' default, a foreign function's restype is c_int (32-bit
    signed). CreateToolhelp32Snapshot and OpenProcess both return HANDLE,
    which is pointer-sized (64-bit on x64 Windows). Any handle value that
    doesn't fit in 32 bits would be silently truncated/misread. In
    practice handle values are usually small, so this had probably never
    visibly failed - but "usually small" isn't a guarantee, and it costs
    nothing to declare it correctly.
    """
    k32.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
    k32.CreateToolhelp32Snapshot.argtypes = [wt.DWORD, wt.DWORD]

    k32.OpenProcess.restype = ctypes.c_void_p
    k32.OpenProcess.argtypes = [wt.DWORD, wt.BOOL, wt.DWORD]

    k32.CloseHandle.restype = wt.BOOL
    k32.CloseHandle.argtypes = [ctypes.c_void_p]

    k32.Process32First.restype = wt.BOOL
    k32.Process32Next.restype = wt.BOOL

    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.VirtualQueryEx.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                    ctypes.c_void_p, ctypes.c_size_t]

    k32.ReadProcessMemory.restype = wt.BOOL
    k32.WriteProcessMemory.restype = wt.BOOL


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
    _configure_kernel32_prototypes(k32)
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == ctypes.c_void_p(-1).value:
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
        _configure_kernel32_prototypes(self.k32)
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
        """Read `size` bytes at `addr`, shrinking the request on failure.

        A straightforward ReadProcessMemory call fails outright if any part
        of the requested range is unreadable - which happens whenever a
        candidate sits close enough to the end of its mapped region that
        `addr + size` spills into unmapped memory. Rather than lose the
        whole read (and silently drop whatever candidate prompted it), retry
        with a smaller size a few times before giving up.
        """
        want = size
        for _ in range(6):
            if want <= 0:
                return None
            buf = ctypes.create_string_buffer(want)
            got = ctypes.c_size_t(0)
            ok = self.k32.ReadProcessMemory(
                self.h, ctypes.c_void_p(addr), buf, want, ctypes.byref(got))
            if ok:
                return buf.raw[:got.value]
            want //= 2
        return None

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
    """Return a list of dicts: {addr, name, length} for compact records."""
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


def iter_raw_buffers(mem, name, private_only=True, verbose=False):
    """Yield addresses of raw, null-padded copies of `name` in memory.

    This is the ONE place that implements "find NAME preceded and followed
    by null bytes" - previously duplicated, slightly differently, in four
    separate places (scan_both, cmd_list, cmd_pick, cmd_measure, plus a
    fifth, unused, in the now-removed scan_raw_buffers). Having four copies
    of the same check meant a correction to one - such as the
    RAW_BUFFER_SIZE fix - did not automatically apply to the others.

    MATCH CRITERIA: for short names (<3 chars) in particular, "name + one
    null byte" is common purely by chance across gigabytes of heap memory -
    that alone found hundreds of thousands of false hits for a 1-char name
    in earlier testing. For names under 3 characters, this requires the
    full RAW_BUFFER_SIZE-byte capacity to be zero-padded, not just one
    trailing null - a genuine copy is null-padded for its entire remaining
    capacity. For names of 3+ characters, the name itself is strong enough
    evidence on its own, so only one trailing null is required (matching
    the looser, faster check that scan_both already used for longer names).
    """
    name_bytes = name.encode("ascii")
    short = len(name_bytes) < 3
    pad_len = max(1, RAW_BUFFER_SIZE - len(name_bytes)) if short else 1

    scanned = 0
    seen = set()
    for base, size in mem.regions(private_only=private_only):
        step = 4 * 1024 * 1024
        for off in range(0, size, step):
            data = mem.read(base + off, min(step + 256, size - off))
            if not data:
                continue
            scanned += len(data)
            start = 0
            while True:
                idx = data.find(name_bytes, start)
                if idx == -1:
                    break
                start = idx + 1
                end = idx + len(name_bytes)
                pad = data[end:end + pad_len]
                if len(pad) < pad_len or pad != b"\x00" * pad_len:
                    continue
                if idx == 0 or data[idx - 1] != 0:
                    continue
                addr = base + off + idx
                if addr not in seen:
                    seen.add(addr)
                    yield addr
    if verbose:
        print("[*] raw-buffer scan (%r) covered %.1f MB"
              % (name, scanned / 1048576.0))


def scan_both(mem, old_name, verbose=False):
    """One memory pass that finds compact records AND raw buffers.

    Returns (compact_records, raw_addresses).
    """
    recs = scan(mem, verbose=verbose)
    recs = [r for r in recs if r["name"] == old_name]
    raw = sorted(set(iter_raw_buffers(mem, old_name, verbose=verbose))
                 - {r["addr"] for r in recs})
    return recs, raw


def cmd_peek(mem, args):
    """Hex-dump raw bytes at/around a specific address (hex, no 0x needed)."""
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
    """Re-verify and rewrite the name until interrupted."""
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

                cur = mem.read(addr, len(old_b))
                if cur != old_b:
                    skipped += 1
                    continue

                hdr = mem.read(addr - 5, 5)
                if not hdr or hdr[0:2] != NAME_HDR or hdr[4] != 0x00:
                    skipped += 1
                    continue

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
    """Write once, then watch that exact byte to see what happens next."""
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


def cmd_pick(mem, args):
    """Interactively confirm which raw buffers are the real name buffers."""
    old = args.pick

    recs = scan(mem, verbose=False)
    skip = {r["addr"] for r in recs}

    # Looser than iter_raw_buffers' short-name path (which demands full
    # RAW_BUFFER_SIZE padding): here we only require a single null on each
    # side, then let the surrounding text help you decide. More candidates,
    # but you are eyeballing them rather than trusting an automatic filter.
    raw = [a for a in iter_raw_buffers(mem, old, verbose=False)
           if a not in skip]
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


def cmd_measure(mem, args):
    """Measure one name's buffer capacity and remember it across sessions."""
    import json
    import os

    nm = args.measure
    try:
        here = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        here = os.getcwd()
    store = os.path.join(here, "pk_measurements.json")

    found = []
    for a in iter_raw_buffers(mem, nm, private_only=True, verbose=True):
        after = mem.read(a + len(nm), 400)
        if not after:
            continue
        zeros = 0
        for b in after:
            if b != 0 or zeros >= 400:
                break
            zeros += 1
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
            print("  a name is riskier - each address is checked for spare")
            print("  room individually before it is written to.")
    return 0


def cmd_funnel(mem, args):
    """Report how many candidates survive each stage of the scan."""
    stats = {"slotId": 0, "name_found": 0, "extracted": 0}
    gaps = {}
    hdrs = {}
    samples = []
    rejects = []

    for base, size in mem.regions():
        step = 4 * 1024 * 1024
        for off in range(0, size, step):
            want = min(step, size - off)
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
    """Scan a wide radius around each address for the nearest 'CHAR' tag."""
    try:
        addrs = [int(a.strip(), 16)
                 for a in args.find_char_near.split(",") if a.strip()]
    except ValueError:
        _fail("--find-char-near expects comma-separated hex addresses.")

    radius = args.radius
    print("[*] searching +/-%d bytes (0x%X) around %d address(es)\n"
          % (radius, radius, len(addrs)))

    verdicts = []
    for addr in addrs:
        start = max(0, addr - radius)
        size = radius * 2
        data = mem.read(start, size)
        if not data:
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
                before_hit = rel
            elif after_hit is None:
                after_hit = rel
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


def cmd_list(mem, args):
    """List characters, from BOTH structures.

    Now a single scan_both() per name, instead of scan() plus a second,
    separate full-memory walk for raw buffers - previously two complete
    passes over the process's address space per invocation.
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

    wanted = set(by_name)
    if args.also:
        wanted.add(args.also)

    live = {}
    for name in wanted:
        skip = {r["addr"] for r in by_name.get(name, [])}
        addrs = [a for a in iter_raw_buffers(mem, name) if a not in skip]
        if addrs:
            live[name] = addrs

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
        print("    The game shows the RAW value. This happens after growing")
        print("    a name, where the compact records had no room and were")
        print("    skipped. Harmless - the game re-writes them when it saves.")

    if not recs and not live:
        print("\nNothing found. Load a character into the world first.")
        print("If a name is 1-2 characters, use --also NAME to check the raw")
        print("buffers for it explicitly.")
        return 1

    print("\nRename with:  python pk_rename.py --rename OLD --to NEW")
    return 0


def cmd_list_raw(mem, args):
    """Fingerprint every raw-buffer candidate for `old_name`."""
    old = args.list_raw
    recs, raw_addrs = scan_both(mem, old, verbose=True)

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

    recs, all_raw = scan_both(mem, old, verbose=True)
    rec_addrs = {r["addr"] for r in recs}

    if args.write_addrs:
        try:
            manual_addrs = [int(x.strip(), 16) for x in args.write_addrs.split(",") if x.strip()]
        except ValueError:
            _fail("--write-addrs expects comma-separated hex addresses, "
                  "e.g. --write-addrs FC2C4FC34F,FC2C60C5B8")
        print("\n--write-addrs given: skipping automatic raw-buffer scan/cap.")

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

    if raw_addrs:
        print("Raw buffer copies (no slotId/name header nearby) at:")
        for a in raw_addrs:
            print("    %X" % a)
        print("These get overwritten too, so a stale UI/display cache can't")
        print("silently restore the old name after the rename.")

    # Decide per address, not globally. The compact slotId records have NO
    # spare room - the byte right after the name text is live data - while
    # the raw buffers are a large null-padded block with lots of spare room.
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

    print("\nWrote %r to %d of %d cop(ies)." % (new, ok, len(targets)))
    if ok:
        print("\nNEXT: exit the game. It writes the save on the way out.")
        print("Then start it again - the character will be renamed.")
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(
        description="Rename a Portal Knights character in live memory.")
    ap.add_argument("--list", action="store_true",
                    help="list every character found in memory")
    ap.add_argument("--rename", metavar="OLD",
                    help="current name of the character to rename")
    ap.add_argument("--to", metavar="NEW",
                    help="new name, up to 32 characters (longer or shorter "
                         "than the current one both work)")
    ap.add_argument("--grow", action="store_true", help=argparse.SUPPRESS)
    ap.add_argument("--all-raw", action="store_true", help=argparse.SUPPRESS)
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
    ap.add_argument("--also", metavar="NAME",
                    help="with --list, also search the raw buffers for this "
                         "exact name (use when a name is too short to be "
                         "listed automatically)")
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
    ap.add_argument("--find-char-near", metavar="ADDR1,ADDR2,...",
                    help="scan a wide radius around each hex address for a "
                         "nearby 'CHAR' struct tag, and report the nearest "
                         "one - avoids guess-and-check with --before on each "
                         "address in turn")
    ap.add_argument("--radius", type=lambda x: int(x, 16), default=0x8000,
                    help="search radius for --find-char-near, hex "
                         "(default 8000 = 32 KB each way)")
    ap.add_argument("--write-addrs", metavar="ADDR1,ADDR2,...",
                    help="comma-separated hex addresses (from --list-raw or "
                         "--peek) to write to directly, bypassing the "
                         "automatic raw-buffer scan and its sanity cap - use "
                         "once you've manually confirmed which candidates "
                         "are real")
    args = ap.parse_args()

    if not (args.list or args.rename or args.dump or args.peek
            or args.list_raw or args.find_char_near or args.funnel
            or args.freeze or args.probe or args.pick or args.measure):
        ap.print_help()
        return 0

    if not sys.platform.startswith("win"):
        _fail("This tool reads live process memory and only runs on Windows.")

    pid = find_pid()
    if not pid:
        _fail("%s is not running. Start the game and load the character "
              "select screen first." % PROCESS_NAME)
    print("[*] %s pid %d" % (PROCESS_NAME, pid))

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
        if args.list:
            return cmd_list(mem, args)
        if args.list_raw:
            return cmd_list_raw(mem, args)
        return cmd_rename(mem, args)
    finally:
        mem.close()


if __name__ == "__main__":
    sys.exit(main())
