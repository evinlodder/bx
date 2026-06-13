Build a terminal binary analysis tool in Rust called "bx".

UI & Layout:
- ratatui + crossterm TUI with a configurable pane layout:
  - Hex view (offset | hex bytes | ASCII sidebar)
  - Structure/annotation pane (user-defined regions with labels and types)
  - Info/output bar at the bottom
- Vim-style keybindings throughout

Dependencies (cargo only, no system packages):
- ratatui + crossterm for TUI
- memmap2 for zero-copy file mapping (important for large firmware blobs)
- md5 crate for file hashing
- serde + serde_json for .bxa annotation files and JSON export

Navigation & Editing:
- Seek to offset with :seek <hex> or g<hex>g
- Hex and ASCII editing modes (toggle with Tab)
- Undo/redo stack for edits
- Visual selection mode (v) with byte range highlighting

Search & Analysis:
- Byte pattern search: /xx xx xx ?? xx (with wildcard support)
- String search (ASCII + UTF-16LE)
- Entropy visualization per region (rendered as a bar graph in-pane)
- XOR brute-force against a selected region (tries keys 0x00-0xFF, shows printable hits)
- Cyclic pattern detection (for recognizing repeating structures)

Diffing:
- Load two files and diff them side by side (:diff <file>)
- Highlight added/removed/changed byte regions with color
- Jump between diff hunks with n/N

Annotations:
- Define named regions: :mark <start> <end> <label> <type>
  - Types: u8, u16le, u16be, u32le, u32be, u64le, u64be, float, str, raw
- Annotations saved to a sidecar file (<binary>.bxa) in a simple text format
- Annotations panel shows parsed value of each marked region live
- Color-coded highlighting of annotated regions in hex view

Structs:
- Define simple structs in a .bxs file (C-struct-like syntax)
- Apply a struct at cursor offset: :applystruct <structname>
- Auto-annotates all fields with parsed values

Architecture Pattern Awareness (heuristic pattern match only, no disassembly):
- Detect and highlight common function prologue/epilogue byte patterns for:
  - x86/x86_64: 55 48 89 E5 (push rbp / mov rbp rsp), C3 (ret), 90 (nop sled)
  - ARM32: PUSH {R4, LR} variants, BX LR epilogues
  - ARM64: STP X29, X30 prologues, RET epilogues
  - MIPS: addiu sp / sw ra patterns
  - PowerPC: mflr r0 / stw r0 prologues
  - RISC-V: addi sp,sp / sd ra patterns
- Flag NOP sleds, int3 sequences, and zero-filled padding regions
- All matches clearly labeled as heuristic in the UI

Magic Byte Detection (scan entire file on load, list all hits with offsets in info pane):
  Executables & objects:
  - ELF (all classes/endians), PE/MZ, Mach-O (32/64/fat), COFF, .a static lib,
    DEX (dex\n035/036/037/038/039), VDEX, OAT, ART, OdexV035

  Firmware & bootloaders:
  - Android boot image v0-v3 (ANDROID!), vendor boot (VNDRBOOT),
    U-Boot uImage/FIT, SquashFS (all endian variants), JFFS2, UBIFS,
    YAFFS2, cramfs, romfs, ext2/3/4, F2FS

  Archives & compression:
  - gzip, zlib (all preset bytes), LZMA, LZ4, Zstandard, bzip2,
    XZ, 7zip, ZIP, RAR, tar

  Certificates & crypto:
  - DER/PEM x509, PKCS#8, PKCS#12, OpenSSH private key,
    Android OTA payload.bin header

  Media & misc:
  - PNG, JPEG, BMP, SQLite3, protobuf (heuristic), msgpack (heuristic)

  On load: parse and display format-specific headers where magic matches:
  - ELF: e_machine, e_entry, e_phoff, section count
  - Android boot image: parse header v0-v3 fields fully
  - PE/MZ: machine type, entrypoint, section table summary
  - DEX: version, class count, checksum

Misc:
- File info on load: size, entropy, detected filetype, MD5
- Jump to offset by hex, decimal, or annotation label
- Export annotated regions to JSON report
- Config file (~/.bxrc) for colors, column width, default pane layout
- cargo install support, include a README with usage
