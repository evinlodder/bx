//! Application state and vim-style key handling.

use std::collections::HashMap;
use std::path::Path;

use crossterm::event::{Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::analysis::arch::{self, ArchHit};
use crate::analysis::magic::{self, MagicHit};
use crate::analysis::{cyclic, entropy, headers, xor};
use crate::annotations::{self, Region};
use crate::buffer::FileBuffer;
use crate::config::Config;
use crate::diff::{self, Hunk};
use crate::export::FileInfo;
use crate::search::SearchState;
use crate::structs::StructDef;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Visual,
    /// Overwrite editing; `ascii` selects the ASCII column, else hex nibbles.
    Edit {
        ascii: bool,
    },
    Command,
    Search,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SideTab {
    Marks,
    Analysis,
    Entropy,
    Output,
}

impl SideTab {
    pub fn next(self) -> Self {
        match self {
            Self::Marks => Self::Analysis,
            Self::Analysis => Self::Entropy,
            Self::Entropy => Self::Output,
            Self::Output => Self::Marks,
        }
    }
}

/// Selections larger than this are truncated before brute-force analysis.
const XOR_CAP: usize = 1 << 20;
const CYCLIC_CAP: usize = 4 << 20;

pub struct App {
    pub config: Config,
    pub buf: FileBuffer,
    pub diff_buf: Option<FileBuffer>,
    pub diff_hunks: Vec<Hunk>,
    pub annotations: Vec<Region>,
    pub structs: HashMap<String, StructDef>,
    pub search: SearchState,
    pub magic_hits: Vec<MagicHit>,
    pub magic_truncated: bool,
    pub arch_hits: Vec<ArchHit>,
    pub arch_truncated: bool,
    pub header_details: Vec<String>,
    pub file_info: FileInfo,
    pub cursor: u64,
    pub view_top: u64,
    /// Hex rows visible last frame; the UI updates this during draw.
    pub view_rows: usize,
    pub mode: Mode,
    /// Waiting for the low nibble of a hex edit.
    pub nibble_low: bool,
    pub visual_anchor: Option<u64>,
    pub last_selection: Option<(u64, u64)>,
    /// Accumulated hex digits of a `g<hex>g` seek, if a `g` is pending.
    pub pending_g: Option<String>,
    pub cmdline: String,
    pub message: String,
    pub output_lines: Vec<String>,
    pub side_tab: SideTab,
    pub side_scroll: u16,
    /// Bucketed whole-file entropy, keyed by bucket count (pane height).
    pub entropy_cache: Option<(usize, Vec<(u64, f64)>)>,
    pub quit: bool,
}

impl App {
    pub fn new(path: &Path, config: Config) -> Result<Self, String> {
        let buf = FileBuffer::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        let mut app = Self {
            config,
            buf,
            diff_buf: None,
            diff_hunks: Vec::new(),
            annotations: Vec::new(),
            structs: HashMap::new(),
            search: SearchState::default(),
            magic_hits: Vec::new(),
            magic_truncated: false,
            arch_hits: Vec::new(),
            arch_truncated: false,
            header_details: Vec::new(),
            file_info: FileInfo {
                size: 0,
                md5: String::new(),
                entropy: 0.0,
                detected_type: "data".into(),
            },
            cursor: 0,
            view_top: 0,
            view_rows: 24,
            mode: Mode::Normal,
            nibble_low: false,
            visual_anchor: None,
            last_selection: None,
            pending_g: None,
            cmdline: String::new(),
            message: String::new(),
            output_lines: Vec::new(),
            side_tab: SideTab::Analysis,
            side_scroll: 0,
            entropy_cache: None,
            quit: false,
        };
        app.reanalyze();
        app.load_sidecars();
        app.message = format!(
            "{} | {} bytes | {} | H={:.2}",
            path.display(),
            app.file_info.size,
            app.file_info.detected_type,
            app.file_info.entropy
        );
        Ok(app)
    }

    /// Whole-file passes: hash, entropy, magic scan, arch heuristics, headers.
    pub fn reanalyze(&mut self) {
        let raw = self.buf.raw();
        let (magic_hits, magic_trunc) = magic::scan(raw);
        let (arch_hits, arch_trunc) = arch::scan(raw);
        self.file_info = FileInfo {
            size: raw.len() as u64,
            md5: format!("{:x}", md5::compute(raw)),
            entropy: entropy::shannon(raw),
            detected_type: magic::detect_type(&magic_hits),
        };
        self.header_details.clear();
        let mut parsed = 0;
        for hit in &magic_hits {
            if parsed >= 6 {
                break;
            }
            if let Some(lines) = headers::parse_for(hit.name, raw, hit.offset as usize) {
                self.header_details
                    .push(format!("── {} @ 0x{:X}", hit.name, hit.offset));
                self.header_details.extend(lines);
                parsed += 1;
            }
        }
        self.magic_hits = magic_hits;
        self.magic_truncated = magic_trunc;
        self.arch_hits = arch_hits;
        self.arch_truncated = arch_trunc;
        self.entropy_cache = None;
    }

    fn load_sidecars(&mut self) {
        match annotations::load_sidecar(&self.buf.path) {
            Ok(Some(bxa)) => {
                if bxa.file_md5 != self.file_info.md5 {
                    self.output_lines.push(
                        "warning: .bxa md5 differs from file (annotations may be stale)".into(),
                    );
                }
                self.annotations = bxa.regions;
                self.annotations.sort_by_key(|r| r.start);
            }
            Ok(None) => {}
            Err(e) => self.output_lines.push(format!("bxa load failed: {e}")),
        }
        let bxs = {
            let mut os = self.buf.path.as_os_str().to_owned();
            os.push(".bxs");
            std::path::PathBuf::from(os)
        };
        if let Ok(text) = std::fs::read_to_string(&bxs) {
            match crate::structs::parse(&text) {
                Ok(map) => self.structs.extend(map),
                Err(e) => self.output_lines.push(format!("bxs parse failed: {e}")),
            }
        }
    }

    pub fn save_annotations(&mut self) {
        if let Err(e) =
            annotations::save_sidecar(&self.buf.path, &self.file_info.md5, &self.annotations)
        {
            self.message = format!("annotation save failed: {e}");
        }
    }

    // --- geometry -------------------------------------------------------------

    pub fn columns(&self) -> u64 {
        self.config.columns as u64
    }

    fn clamp(&self, off: u64) -> u64 {
        off.min(self.buf.len().saturating_sub(1))
    }

    pub fn move_cursor(&mut self, to: u64) {
        if self.buf.is_empty() {
            return;
        }
        self.cursor = self.clamp(to);
        self.nibble_low = false;
        self.ensure_visible();
    }

    fn ensure_visible(&mut self) {
        let cols = self.columns();
        let rows = self.view_rows.max(1) as u64;
        let cursor_row = self.cursor / cols;
        let top_row = self.view_top / cols;
        if cursor_row < top_row {
            self.view_top = cursor_row * cols;
        } else if cursor_row >= top_row + rows {
            self.view_top = (cursor_row + 1 - rows) * cols;
        }
    }

    pub fn selection(&self) -> Option<(u64, u64)> {
        if self.mode == Mode::Visual {
            let a = self.visual_anchor?;
            Some((a.min(self.cursor), a.max(self.cursor) + 1))
        } else {
            None
        }
    }

    /// Active selection, else the one remembered from the last visual mode.
    fn selection_or_last(&self) -> Option<(u64, u64)> {
        self.selection().or(self.last_selection)
    }

    fn leave_visual(&mut self) {
        if let Some(sel) = self.selection() {
            self.last_selection = Some(sel);
        }
        self.visual_anchor = None;
    }

    // --- events ---------------------------------------------------------------

    pub fn handle_event(&mut self, ev: Event) {
        if let Event::Key(key) = ev
            && key.kind == KeyEventKind::Press
        {
            self.handle_key(key);
        }
    }

    pub fn handle_key(&mut self, key: KeyEvent) {
        match self.mode {
            Mode::Command | Mode::Search => self.handle_line_input(key),
            Mode::Edit { ascii } => self.handle_edit(key, ascii),
            Mode::Normal | Mode::Visual => self.handle_normal(key),
        }
    }

    fn handle_normal(&mut self, key: KeyEvent) {
        // g<hex>g pending sequence takes priority over normal bindings.
        if let Some(digits) = self.pending_g.take() {
            match key.code {
                KeyCode::Char('g') => {
                    if digits.is_empty() {
                        self.move_cursor(0); // gg
                    } else if let Ok(off) = u64::from_str_radix(&digits, 16) {
                        self.move_cursor(off);
                        self.message = format!("seek 0x{:X}", self.cursor);
                    }
                }
                KeyCode::Char(c) if c.is_ascii_hexdigit() => {
                    self.pending_g = Some(format!("{digits}{c}"));
                }
                _ => self.message.clear(), // cancel
            }
            return;
        }

        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        let cols = self.columns();
        match key.code {
            KeyCode::Char('g') if !ctrl => {
                self.pending_g = Some(String::new());
                self.message = "g…g (hex offset)".into();
            }
            KeyCode::Char('h') | KeyCode::Left => self.move_cursor(self.cursor.saturating_sub(1)),
            KeyCode::Char('l') | KeyCode::Right => self.move_cursor(self.cursor + 1),
            KeyCode::Char('j') | KeyCode::Down => self.move_cursor(self.cursor + cols),
            KeyCode::Char('k') | KeyCode::Up => self.move_cursor(self.cursor.saturating_sub(cols)),
            KeyCode::Char('w') => self.move_cursor(self.cursor + cols),
            KeyCode::Char('b') if !ctrl => self.move_cursor(self.cursor.saturating_sub(cols)),
            KeyCode::Char('0') => self.move_cursor(self.cursor - self.cursor % cols),
            KeyCode::Char('$') => self.move_cursor(self.cursor - self.cursor % cols + cols - 1),
            KeyCode::Char('d') if ctrl => {
                self.move_cursor(self.cursor + (self.view_rows as u64 / 2) * cols)
            }
            KeyCode::Char('u') if ctrl => self.move_cursor(
                self.cursor
                    .saturating_sub((self.view_rows as u64 / 2) * cols),
            ),
            KeyCode::Char('f') if ctrl => {
                self.move_cursor(self.cursor + self.view_rows as u64 * cols)
            }
            KeyCode::Char('b') if ctrl => {
                self.move_cursor(self.cursor.saturating_sub(self.view_rows as u64 * cols))
            }
            KeyCode::PageDown => self.move_cursor(self.cursor + self.view_rows as u64 * cols),
            KeyCode::PageUp => {
                self.move_cursor(self.cursor.saturating_sub(self.view_rows as u64 * cols))
            }
            KeyCode::Char('G') | KeyCode::End => self.move_cursor(u64::MAX),
            KeyCode::Home => self.move_cursor(0),
            KeyCode::Char(':') => {
                self.leave_visual();
                self.mode = Mode::Command;
                self.cmdline.clear();
            }
            KeyCode::Char('/') => {
                self.leave_visual();
                self.mode = Mode::Search;
                self.cmdline.clear();
            }
            KeyCode::Char('v') => {
                if self.mode == Mode::Visual {
                    self.leave_visual();
                    self.mode = Mode::Normal;
                } else if !self.buf.is_empty() {
                    self.visual_anchor = Some(self.cursor);
                    self.mode = Mode::Visual;
                }
            }
            KeyCode::Esc => {
                if self.mode == Mode::Visual {
                    self.leave_visual();
                    self.mode = Mode::Normal;
                }
                self.message.clear();
            }
            KeyCode::Char('i') | KeyCode::Insert if self.mode == Mode::Normal => {
                if self.buf.is_empty() {
                    self.message = "empty file".into();
                } else {
                    self.mode = Mode::Edit { ascii: false };
                    self.nibble_low = false;
                    self.message = "-- EDIT (hex) -- Tab toggles ASCII, Esc ends".into();
                }
            }
            KeyCode::Char('u') => match self.buf.undo() {
                Some(off) => {
                    self.move_cursor(off);
                    self.message = format!("undo @ 0x{off:X}");
                }
                None => self.message = "nothing to undo".into(),
            },
            KeyCode::Char('r') if ctrl => match self.buf.redo() {
                Some(off) => {
                    self.move_cursor(off);
                    self.message = format!("redo @ 0x{off:X}");
                }
                None => self.message = "nothing to redo".into(),
            },
            KeyCode::Char('n') => self.nav_next(true),
            KeyCode::Char('N') => self.nav_next(false),
            KeyCode::Char('}') => self.magic_nav(true),
            KeyCode::Char('{') => self.magic_nav(false),
            KeyCode::Char('x') => match self.selection_or_last() {
                Some((s, e)) => {
                    if self.mode == Mode::Visual {
                        self.leave_visual();
                        self.mode = Mode::Normal;
                    }
                    self.run_xor(s, e);
                }
                None => self.message = "no selection (use v first)".into(),
            },
            KeyCode::Char('c') => match self.selection_or_last() {
                Some((s, e)) => {
                    if self.mode == Mode::Visual {
                        self.leave_visual();
                        self.mode = Mode::Normal;
                    }
                    self.run_cyclic(s, e);
                }
                None => self.message = "no selection (use v first)".into(),
            },
            KeyCode::Char('m') if self.mode == Mode::Visual => {
                let (s, e) = self.selection().unwrap();
                self.leave_visual();
                self.cmdline = format!("mark 0x{s:X} 0x{e:X} ");
                self.mode = Mode::Command;
            }
            KeyCode::Char('e') => {
                self.side_tab = if self.side_tab == SideTab::Entropy {
                    SideTab::Marks
                } else {
                    SideTab::Entropy
                };
                self.side_scroll = 0;
            }
            KeyCode::Tab => {
                self.side_tab = self.side_tab.next();
                self.side_scroll = 0;
            }
            KeyCode::Char('J') => self.side_scroll = self.side_scroll.saturating_add(1),
            KeyCode::Char('K') => self.side_scroll = self.side_scroll.saturating_sub(1),
            KeyCode::Char('<') => {
                self.config.anno_width = self.config.anno_width.saturating_sub(2).max(15);
            }
            KeyCode::Char('>') => {
                self.config.anno_width = (self.config.anno_width + 2).min(120);
            }
            KeyCode::Char('q') => {
                if self.buf.has_unsaved_changes() {
                    self.message = "unsaved changes (:w to save, :q! to discard)".into();
                } else {
                    self.quit = true;
                }
            }
            _ => {}
        }
    }

    fn handle_edit(&mut self, key: KeyEvent, ascii: bool) {
        let cols = self.columns();
        match key.code {
            KeyCode::Esc => {
                self.buf.commit_group();
                self.nibble_low = false;
                self.mode = Mode::Normal;
                self.message.clear();
            }
            KeyCode::Tab => {
                self.nibble_low = false;
                self.mode = Mode::Edit { ascii: !ascii };
                self.message = if ascii {
                    "-- EDIT (hex) --".into()
                } else {
                    "-- EDIT (ascii) --".into()
                };
            }
            KeyCode::Left => self.move_cursor(self.cursor.saturating_sub(1)),
            KeyCode::Right => self.move_cursor(self.cursor + 1),
            KeyCode::Down => self.move_cursor(self.cursor + cols),
            KeyCode::Up => self.move_cursor(self.cursor.saturating_sub(cols)),
            KeyCode::Backspace => self.move_cursor(self.cursor.saturating_sub(1)),
            KeyCode::Char(c) => {
                if ascii {
                    if (' '..='~').contains(&c) {
                        self.buf.set(self.cursor, c as u8);
                        self.move_cursor(self.cursor + 1);
                    }
                } else if let Some(d) = c.to_digit(16) {
                    let cur = self.buf.get(self.cursor).unwrap_or(0);
                    if self.nibble_low {
                        self.buf.set(self.cursor, cur & 0xF0 | d as u8);
                        let next = self.cursor + 1;
                        self.move_cursor(next); // resets nibble_low
                    } else {
                        self.buf.set(self.cursor, (d as u8) << 4 | cur & 0x0F);
                        self.nibble_low = true;
                    }
                }
            }
            _ => {}
        }
    }

    fn handle_line_input(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.cmdline.clear();
                self.mode = Mode::Normal;
            }
            KeyCode::Backspace => {
                if self.cmdline.pop().is_none() {
                    self.mode = Mode::Normal;
                }
            }
            KeyCode::Enter => {
                let line = std::mem::take(&mut self.cmdline);
                let was_search = self.mode == Mode::Search;
                self.mode = Mode::Normal;
                if was_search {
                    self.execute_search(&line);
                } else {
                    crate::commands::execute(self, &line);
                }
            }
            KeyCode::Char(c) => self.cmdline.push(c),
            _ => {}
        }
    }

    // --- actions ----------------------------------------------------------------

    pub fn execute_search(&mut self, query: &str) {
        match crate::search::run_search(&self.buf, query) {
            Ok(state) => {
                let n = state.hits.len();
                self.search = state;
                if n == 0 {
                    self.message = format!("no matches for {query}");
                } else {
                    // Jump to the first hit at or after the cursor.
                    let from = self.cursor;
                    let idx = self
                        .search
                        .hits
                        .iter()
                        .position(|&(s, _)| s >= from)
                        .unwrap_or(0);
                    self.search.current = idx;
                    let (s, _) = self.search.hits[idx];
                    self.move_cursor(s);
                    self.message = format!("{n} match(es) | n/N to cycle");
                }
            }
            Err(e) => self.message = format!("search: {e}"),
        }
    }

    /// n/N: diff hunks while a diff is loaded, else search hits.
    fn nav_next(&mut self, forward: bool) {
        if self.diff_buf.is_some() {
            let h = if forward {
                diff::next_hunk(&self.diff_hunks, self.cursor)
            } else {
                diff::prev_hunk(&self.diff_hunks, self.cursor)
            };
            match h {
                Some(h) => {
                    let (start, kind) = (h.start, h.kind);
                    self.move_cursor(start);
                    self.message = format!("hunk {kind:?} @ 0x{start:X}");
                }
                None => self.message = "no diff hunks".into(),
            }
        } else {
            let hit = if forward {
                self.search.next(self.cursor)
            } else {
                self.search.prev(self.cursor)
            };
            match hit {
                Some((s, _)) => {
                    self.move_cursor(s);
                    self.message = format!(
                        "match {}/{}",
                        self.search.current + 1,
                        self.search.hits.len()
                    );
                }
                None => self.message = "no search hits (use /)".into(),
            }
        }
    }

    fn magic_nav(&mut self, forward: bool) {
        if self.magic_hits.is_empty() {
            self.message = "no magic hits".into();
            return;
        }
        let hit = if forward {
            self.magic_hits
                .iter()
                .find(|h| h.offset > self.cursor)
                .or(self.magic_hits.first())
        } else {
            self.magic_hits
                .iter()
                .rev()
                .find(|h| h.offset < self.cursor)
                .or(self.magic_hits.last())
        };
        if let Some(h) = hit {
            let (off, name) = (h.offset, h.name);
            self.move_cursor(off);
            self.message = format!("{name} @ 0x{off:X}");
        }
    }

    pub fn run_xor(&mut self, start: u64, end: u64) {
        let len = ((end - start) as usize).min(XOR_CAP);
        let data = self.buf.get_range(start, len);
        let hits = xor::brute_force(&data, 0.85);
        self.output_lines = vec![format!(
            "XOR brute-force 0x{start:X}..0x{end:X} ({} bytes{}):",
            data.len(),
            if (end - start) as usize > XOR_CAP {
                ", capped"
            } else {
                ""
            }
        )];
        if hits.is_empty() {
            self.output_lines
                .push("no printable candidates ≥85%".into());
        }
        for h in hits.iter().take(16) {
            self.output_lines.push(format!(
                "key 0x{:02X}  {:5.1}%  {}",
                h.key,
                h.printable_ratio * 100.0,
                h.preview
            ));
        }
        self.side_tab = SideTab::Output;
        self.side_scroll = 0;
        self.message = format!("{} XOR candidate(s)", hits.len());
    }

    pub fn run_cyclic(&mut self, start: u64, end: u64) {
        let len = ((end - start) as usize).min(CYCLIC_CAP);
        let data = self.buf.get_range(start, len);
        let hits = cyclic::detect(&data, 64, 0.90);
        self.output_lines = vec![format!(
            "Cyclic pattern scan 0x{start:X}..0x{end:X} ({} bytes): [heuristic]",
            data.len()
        )];
        if hits.is_empty() {
            self.output_lines
                .push("no repeating structure found".into());
        }
        for h in hits.iter().take(8) {
            self.output_lines.push(format!(
                "period {:3} bytes  self-similarity {:5.1}%",
                h.period,
                h.score * 100.0
            ));
        }
        self.side_tab = SideTab::Output;
        self.side_scroll = 0;
        self.message = format!("{} cyclic candidate(s)", hits.len());
    }

    pub fn start_diff(&mut self, path: &Path) -> Result<(), String> {
        let other = FileBuffer::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
        self.diff_hunks = diff::compute(self.buf.raw(), other.raw(), 4);
        let n = self.diff_hunks.len();
        self.diff_buf = Some(other);
        self.message = format!("diff: {n} hunk(s) | n/N to jump, :diffoff to close");
        Ok(())
    }

    /// File info + analysis summary; feeds the Analysis tab and --batch mode.
    pub fn info_lines(&self) -> Vec<String> {
        let mut out = vec![
            format!("file: {}", self.buf.path.display()),
            format!(
                "size: {} (0x{:X})",
                self.file_info.size, self.file_info.size
            ),
            format!("type: {}", self.file_info.detected_type),
            format!("entropy: {:.4} bits/byte", self.file_info.entropy),
            format!("md5: {}", self.file_info.md5),
            String::new(),
            format!(
                "magic hits: {}{}",
                self.magic_hits.len(),
                if self.magic_truncated {
                    " (truncated)"
                } else {
                    ""
                }
            ),
        ];
        for h in self.magic_hits.iter().take(200) {
            out.push(format!("  0x{:08X}  {} [{}]", h.offset, h.name, h.category));
        }
        if self.magic_hits.len() > 200 {
            out.push(format!("  … {} more", self.magic_hits.len() - 200));
        }
        if !self.header_details.is_empty() {
            out.push(String::new());
            out.extend(self.header_details.iter().cloned());
        }
        out.push(String::new());
        out.push(format!(
            "arch patterns [heuristic]: {} hit(s){}",
            self.arch_hits.len(),
            if self.arch_truncated {
                " (truncated)"
            } else {
                ""
            }
        ));
        let mut counts: std::collections::BTreeMap<(&str, &str), usize> =
            std::collections::BTreeMap::new();
        for h in &self.arch_hits {
            *counts.entry((h.arch, h.desc)).or_default() += 1;
        }
        for ((arch, desc), n) in counts {
            out.push(format!("  {arch:<12} {desc:<36} ×{n}"));
        }
        out
    }
}
