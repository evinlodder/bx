//! `:` command parsing and execution.

use std::path::{Path, PathBuf};

use crate::annotations::{Region, RegionType};
use crate::app::{App, SideTab};
use crate::export;

/// Jump-target syntax: annotation label, `0x` hex, `0d` decimal, bare hex.
pub fn parse_offset(s: &str, regions: &[Region]) -> Option<u64> {
    if let Some(r) = regions.iter().find(|r| r.label == s) {
        return Some(r.start);
    }
    if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(h, 16).ok()
    } else if let Some(d) = s.strip_prefix("0d") {
        d.parse().ok()
    } else {
        u64::from_str_radix(s, 16).ok()
    }
}

pub fn execute(app: &mut App, line: &str) {
    let line = line.trim();
    if line.is_empty() {
        return;
    }
    let mut parts = line.split_whitespace();
    let cmd = parts.next().unwrap();
    let args: Vec<&str> = parts.collect();
    match cmd {
        "seek" => cmd_seek(app, &args),
        "mark" => cmd_mark(app, &args),
        "unmark" => cmd_unmark(app, &args),
        "xor" => match app.last_selection {
            Some((s, e)) => app.run_xor(s, e),
            None => app.message = "xor: no selection (use v to select first)".into(),
        },
        "cyclic" => match app.last_selection {
            Some((s, e)) => app.run_cyclic(s, e),
            None => app.message = "cyclic: no selection".into(),
        },
        "diff" => match args.first() {
            Some(f) => {
                if let Err(e) = app.start_diff(Path::new(f)) {
                    app.message = format!("diff: {e}");
                }
            }
            None => app.message = "usage: :diff <file>".into(),
        },
        "diffoff" => {
            app.diff_buf = None;
            app.diff_hunks.clear();
            app.message = "diff closed".into();
        }
        "applystruct" => cmd_applystruct(app, &args),
        "loadstructs" => cmd_loadstructs(app, &args),
        "export" => cmd_export(app, &args),
        "checksum" | "cksum" | "hash" => cmd_checksum(app, &args),
        "e" | "edit" | "open" => cmd_open(app, &args),
        "bn" | "bnext" => app.switch_file(1),
        "bp" | "bprev" => app.switch_file(-1),
        "b" | "buffer" => cmd_buffer(app, &args),
        "ls" | "files" | "buffers" => cmd_files(app),
        "close" | "bd" => app.request_close(false),
        "bd!" => app.request_close(true),
        "w" | "wq" => {
            let target = args.first().map(PathBuf::from);
            match app.buf.save(target.as_deref()) {
                Ok(path) => {
                    if target.is_none() {
                        // In-place patch changes hash/entropy/magic landscape.
                        app.reanalyze();
                    }
                    app.save_annotations();
                    app.message = format!("wrote {}", path.display());
                    if cmd == "wq" {
                        app.request_close(false);
                    }
                }
                Err(e) => app.message = format!("write failed: {e}"),
            }
        }
        "revert" => {
            if app.buf.has_unsaved_changes() {
                app.buf.discard_edits();
                app.message = "reverted unsaved edits".into();
            } else {
                app.message = "no unsaved edits".into();
            }
        }
        "q" => app.request_close(false),
        "q!" => app.request_close(true),
        "qa" | "qall" => {
            if app.docs.iter().any(|d| d.buf.has_unsaved_changes()) {
                app.message = "unsaved changes in some files (:qa! to discard all)".into();
            } else {
                app.quit = true;
            }
        }
        "qa!" | "qall!" => app.quit = true,
        "info" => {
            app.side_tab = SideTab::Analysis;
            app.side_scroll = 0;
        }
        "inspect" => {
            app.side_tab = SideTab::Inspect;
            app.side_scroll = 0;
        }
        "entropy" => {
            app.side_tab = SideTab::Entropy;
            app.side_scroll = 0;
        }
        "help" => {
            app.output_lines = HELP.lines().map(String::from).collect();
            app.side_tab = SideTab::Output;
            app.side_scroll = 0;
        }
        _ => app.message = format!("unknown command :{cmd} (:help)"),
    }
}

fn cmd_seek(app: &mut App, args: &[&str]) {
    let Some(target) = args.first() else {
        app.message = "usage: :seek <hex|0d<dec>|label>".into();
        return;
    };
    match parse_offset(target, &app.annotations) {
        Some(off) if off < app.buf.len() => {
            app.move_cursor(off);
            app.message = format!("seek 0x{:X}", app.cursor);
        }
        Some(off) => app.message = format!("0x{off:X} is past EOF (size 0x{:X})", app.buf.len()),
        None => app.message = format!("can't parse offset or label '{target}'"),
    }
}

fn cmd_mark(app: &mut App, args: &[&str]) {
    if args.len() != 4 {
        app.message = "usage: :mark <start> <end> <label> <type>  (end exclusive)".into();
        return;
    }
    let (start, end) = match (
        parse_offset(args[0], &app.annotations),
        parse_offset(args[1], &app.annotations),
    ) {
        (Some(s), Some(e)) => (s, e),
        _ => {
            app.message = format!("bad offsets '{} {}'", args[0], args[1]);
            return;
        }
    };
    if start >= end || end > app.buf.len() {
        app.message = format!(
            "bad range 0x{start:X}..0x{end:X} (file size 0x{:X})",
            app.buf.len()
        );
        return;
    }
    let label = args[2].to_string();
    let Some(rtype) = RegionType::parse(args[3]) else {
        app.message = format!(
            "unknown type '{}' (u8 u16le u16be u32le u32be u64le u64be float str raw)",
            args[3]
        );
        return;
    };
    if let Some(size) = rtype.fixed_size()
        && end - start != size
    {
        app.message = format!(
            "{rtype} needs exactly {size} byte(s), range is {}",
            end - start
        );
        return;
    }
    app.annotations.retain(|r| r.label != label);
    app.annotations.push(Region {
        start,
        end,
        label: label.clone(),
        rtype,
    });
    app.annotations.sort_by_key(|r| r.start);
    app.save_annotations();
    app.side_tab = SideTab::Marks;
    app.message = format!("marked {label} @ 0x{start:X}..0x{end:X}");
}

fn cmd_unmark(app: &mut App, args: &[&str]) {
    let Some(label) = args.first() else {
        app.message = "usage: :unmark <label>".into();
        return;
    };
    let before = app.annotations.len();
    app.annotations.retain(|r| &r.label != label);
    if app.annotations.len() < before {
        app.save_annotations();
        app.message = format!("unmarked {label}");
    } else {
        app.message = format!("no annotation '{label}'");
    }
}

fn cmd_applystruct(app: &mut App, args: &[&str]) {
    let Some(name) = args.first() else {
        let known: Vec<&str> = app.structs.keys().map(String::as_str).collect();
        app.message = format!("usage: :applystruct <name>; loaded: {}", known.join(", "));
        return;
    };
    let Some(def) = app.structs.get(*name) else {
        app.message = format!("no struct '{name}' (load via <file>.bxs or :loadstructs)");
        return;
    };
    let total = def.total_size();
    if app.cursor + total > app.buf.len() {
        app.message = format!("struct {name} (0x{total:X} bytes) overruns EOF at cursor");
        return;
    }
    let regions = def.apply(app.cursor);
    let n = regions.len();
    for r in regions {
        app.annotations.retain(|x| x.label != r.label);
        app.annotations.push(r);
    }
    app.annotations.sort_by_key(|r| r.start);
    app.save_annotations();
    app.side_tab = SideTab::Marks;
    app.message = format!("applied {name}: {n} field(s) @ 0x{:X}", app.cursor);
}

fn cmd_loadstructs(app: &mut App, args: &[&str]) {
    let Some(file) = args.first() else {
        app.message = "usage: :loadstructs <file.bxs>".into();
        return;
    };
    match std::fs::read_to_string(file) {
        Ok(text) => match crate::structs::parse(&text) {
            Ok(map) => {
                let names: Vec<String> = map.keys().cloned().collect();
                app.structs.extend(map);
                app.message = format!("loaded struct(s): {}", names.join(", "));
            }
            Err(e) => app.message = format!("{file}: {e}"),
        },
        Err(e) => app.message = format!("{file}: {e}"),
    }
}

fn cmd_checksum(app: &mut App, args: &[&str]) {
    let range = if args.is_empty() {
        // last visual selection, else whole file
        app.last_selection
    } else if args.len() == 2 {
        match (
            parse_offset(args[0], &app.annotations),
            parse_offset(args[1], &app.annotations),
        ) {
            (Some(s), Some(e)) if s < e && e <= app.buf.len() => Some((s, e)),
            _ => {
                app.message = format!("bad range '{} {}'", args[0], args[1]);
                return;
            }
        }
    } else {
        app.message = "usage: :checksum [start end]  (default: selection or whole file)".into();
        return;
    };
    app.run_checksum(range);
}

fn cmd_open(app: &mut App, args: &[&str]) {
    let Some(file) = args.first() else {
        app.message = "usage: :e <file>".into();
        return;
    };
    if let Err(e) = app.open_file(Path::new(file)) {
        app.message = format!("open: {e}");
    }
}

fn cmd_buffer(app: &mut App, args: &[&str]) {
    let Some(n) = args.first().and_then(|s| s.parse::<usize>().ok()) else {
        app.message = "usage: :b <n>".into();
        return;
    };
    app.goto_file(n.saturating_sub(1));
}

fn cmd_files(app: &mut App) {
    let mut lines = vec![format!("{} open file(s):", app.docs.len())];
    for (i, d) in app.docs.iter().enumerate() {
        let marker = if i == app.active { '>' } else { ' ' };
        let dirty = if d.buf.has_unsaved_changes() { " [+]" } else { "" };
        lines.push(format!("{marker} {}: {}{}", i + 1, d.buf.path.display(), dirty));
    }
    app.output_lines = lines;
    app.side_tab = SideTab::Output;
    app.side_scroll = 0;
}

fn cmd_export(app: &mut App, args: &[&str]) {
    let Some(out) = args.first() else {
        app.message = "usage: :export <report.json>".into();
        return;
    };
    match export::write_report(Path::new(out), &app.buf, &app.file_info, &app.annotations) {
        Ok(()) => app.message = format!("exported {} region(s) to {out}", app.annotations.len()),
        Err(e) => app.message = format!("export: {e}"),
    }
}

const HELP: &str = "\
bx commands:
  :seek <hex|0d<dec>|label>     jump (also g<hex>g, gg, G)
  :mark <start> <end> <label> <type>   annotate region (end exclusive)
  :unmark <label>               remove annotation
  :applystruct <name>           lay struct fields down at cursor
  :loadstructs <file.bxs>       load struct definitions
  :diff <file> / :diffoff       side-by-side diff (n/N jump hunks)
  :xor / :cyclic                analyze last visual selection (also x / c)
  :checksum [start end]         CRC/MD5/SHA of selection or file (also #)
  :export <file.json>           JSON report of annotations
  files: :e <f> open · :bn/:bp/:b<n> switch · :ls list · :close · gt/gT
  :w [file] | :q | :q! | :wq | :qa    write / quit
  :info | :inspect | :entropy | :help   side-pane tabs
keys: hjkl move · v select · i edit (Tab hex/ascii) · u undo · C-r redo
      / search ('?? '=wildcard, \"text\"=string) · n/N next/prev · {/} magic hits
      Tab cycle side pane · J/K scroll · >/< resize · # checksum · e entropy";
