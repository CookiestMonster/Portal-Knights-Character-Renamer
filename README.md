# Portal Knights — Character Renamer

Renames a Portal Knights character by editing the running game's memory, then
letting the game write its own save. Tested against **Portal Knights 1.7.2**
(PC / Steam).

Portal Knights has no rename feature — a Keen Games developer confirmed this
on the Steam forums back in 2017. This is a workaround.

1. **Back up your character file (this is all of your characters 9 Slots).**
2. 
Steam cloud is on (change your ID to your ID it will be like 915394459, 9 digits if you cant find it just go to before your userdata)
   ```
copy "C:\Program Files (x86)\Steam\userdata\<your-id>\374040\remote\0100000000000000" "%USERPROFILE%\Downloads\pk_bk_01"
   ```
OR 
Steam cloud is off (Change your user to your computer name)
   ```
"C:\Users"your_user"\Saved Games\portal_knights\0100000000000000" "%USERPROFILE%\Downloads\pk_bk_01"
   ```

Split-screen / Guest profiles

Player 2's characters live in a Guest subfolder:
   ```
%USERPROFILE%\Saved Games\portal_knights\Guest\0100000000000000
   ```

   `0100000000000000` holds **all** your characters — that is the one that
   matters. (`0200000000000000` is the game's own backup of it. Leave it
   alone; if `0100` ever breaks, the character select screen offers to
   restore from it.)

2. **Load into the game with the character you want to rename.** Being
   actually in the world with that character is what puts its name buffers
   in memory.

3. Open a Command Prompt **as Administrator** and run:

   ```
   python pk_rename.py --rename OLDNAME --to NEWNAME
   ```

   **Names are case sensitive.** `boom` will not match a character called
   `BOOM`.

   Any name up to **32 characters** works — longer or shorter than the
   current one, it makes no difference.

4. **Exit the game.** It writes the save on the way out.

5. Start it again — the character is renamed.

`--list` shows what the tool can see, in both structures. After growing a
name the two will disagree — the compact records keep the old name because
they have no spare padding, while the raw buffers (what the game displays)
hold the new one. `--list` points this out rather than looking like a failure.
The game rewrites the compact records itself when it saves.

---

## Name length

Measured from live memory: the name sits in a **fixed 128-byte buffer**,
null-padded. A 32-character name leaves exactly 96 trailing nulls
(32 + 96 = 128), and six separate copies agreed. There is no separate length
field, so the string is read to its null terminator.

The **game's own limit is 32 characters**, and the tool refuses anything
longer.

Growing and shrinking are both automatic. Each address is checked
individually: the compact `slotId` records have live data immediately after
the name and no spare room, while the raw buffers have ~96–127 spare bytes.
Addresses with room are written, the rest are skipped and reported.

To re-measure on a future game version:

```
python pk_rename.py --measure SOMENAME
```

Results accumulate in `pk_measurements.json` so names measured in separate
sessions can be compared — you can only be logged in as one character at a
time. Use names of 4+ characters; shorter ones match by chance and the
measurement is meaningless.

---

## Where the name actually lives

Two structures hold it, and only one matters:

| Structure | Typical count | Is it what the game displays? |
|---|---|---|
| Compact `slotId`/`name` records | ~3 | No — serialisation scaffolding |
| Raw null-padded buffers | 8–50 | **Yes** |

Writing only the compact records changes nothing visible. Filtering the raw
buffers down to those referenced by a plain 8-byte pointer also fails — it
kept 2 of 52 candidates for a one-character name and the rename silently did
nothing. The game reaches the display buffer another way, so **every** raw
candidate is written. Each is the old name sitting in null padding, so a
stray write lands in dead space.

A character may have **no compact record at all** and still rename correctly.

---

## Why the save file cannot be edited directly

The save container starts with magic `KSC1`:

```
0-3    "KSC1"
4-7    version (1)
8-23   16-byte checksum
24-27  zero
28-31  type tag — "CHAR" for character files
32-35  first chunk size
```

Change a single byte of the payload and the game rejects the file with a save
data error. The checksum at bytes 8–23 could not be reproduced: MD5, SHA-1,
SHA-2, SHA-3, BLAKE2, CRC32, Adler32, xxHash (32/64/3-128), MurmurHash3,
CityHash128 and FarmHash128 were all ruled out against a known save. It is
likely keyed or custom.

Editing live memory sidesteps this entirely, because the game computes its own
valid checksum when it saves.

The payload itself is zstd-compressed using a dictionary embedded in
`portal_knights_x64.exe` (offset `0x8096C0`, length 262144, dict ID
`0x206A547B`).

---

## Record layout

Each character is stored as an SNPY record:

```
SNPY  Entity  TemplateCRC  CreationParameter  Position  ComponentData
ceda2313  CharacterSetup  slotId  name  customiz  modelIds  texture
effectPackage  color  rac  class  price  playtime  last  level  gender
guid  RecipeKnowledgeList  Talent Line  Crafting  Quest  State
```

The name field, verified byte-for-byte in both the save file and live memory:

```
save file : 6E 61 6D 65 | 00 80 | 01 0C 00 | 41 | 01 05 FE ...
live mem  : 6E 61 6D 65 | 00 80 | 01 64 00 | 41 | 01 05 FE ...
             n  a  m  e            ^^          ^^
                              varies      the name text
```

The header is a fixed 5 bytes (`00 80 01 XX 00`), so the text always begins at
`name+9`. That middle byte varies and is often printable — `0x64` is `d`,
`0x65` is `e` — which will fool any scanner that looks for "the first printable
run" instead of reading the fixed offset.

An empty-name record looks like `name 00 00 templateCRC` and is skipped.

---

## All options

```
--list                 list characters found in memory
--find NAME            with --list, also search raw buffers for this exact
                       name (needed when it has no compact record)
--rename OLD --to NEW  rename a character (this is all you need)
--dry-run              show what would be written, change nothing
--funnel               diagnostic: how many candidates survive each scan stage
--probe OLD            write once, then watch the bytes for 10s
--peek ADDR            hex-dump around a specific address
--dump N               hex-dump the first N slotId hits
--pick OLD             list raw candidates with surrounding text
--list-raw OLD         list raw candidates with byte fingerprints
--write-addrs A,B,C    write only to specific confirmed addresses
--find-char-near A,B   find the nearest CHAR tag to given addresses
--freeze OLD --to NEW  rewrite continuously until Ctrl+C
```

Addresses are only valid for the current run of the game. Restart it and they
are meaningless — rescan.

---

## Requirements

- Windows, Python 3.8+
- Run as Administrator (the game is under `C:\Program Files (x86)`)
- No third-party packages — `ctypes` only

---

## Credits

The `Find Inventory Base` script referenced during development comes from
Artykalamata/Kai's Cheat Engine table for Portal Knights 1.6.1. Their
`Find Player Base` script no longer installs on 1.7.2 — its AOB signature
`F3 0F 11 7F 08 E8` was changed by a game update. That one script still working
while the other did not was the clue that the process was hookable and the
tooling was fine.
