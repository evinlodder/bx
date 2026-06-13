//! Side pane: tabbed Marks / Analysis / Entropy / Output views.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Wrap};

use crate::analysis::{entropy, strings};
use crate::app::{App, SideTab};
use crate::inspector;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let block = Block::bordered();
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let titles: Vec<&str> = SideTab::ORDER.iter().map(|t| tab_title(*t)).collect();
    let selected = SideTab::ORDER
        .iter()
        .position(|&t| t == app.side_tab)
        .unwrap_or(0);
    // Single-row carousel: scrolls to keep the active tab centred, with </>
    // edge hints when more tabs exist off-screen.
    let [tab_area, body] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);
    frame.render_widget(
        Paragraph::new(tab_header_line(&titles, selected, inner.width)),
        tab_area,
    );

    // Marks and Strings are pre-windowed for speed, so they manage their own
    // scroll; the rest use the shared scroll offset with wrapping.
    let (lines, scroll, wrap): (Vec<Line>, u16, bool) = match app.side_tab {
        SideTab::Marks => (marks_lines(app, body), 0, false),
        SideTab::Template => (template_lines(app), app.side_scroll, false),
        SideTab::Inspect => (inspect_lines(app), app.side_scroll, true),
        SideTab::Strings => (strings_lines(app, body), 0, false),
        SideTab::Analysis => (
            app.info_lines().into_iter().map(Line::from).collect(),
            app.side_scroll,
            true,
        ),
        SideTab::Entropy => (entropy_lines(app, body), app.side_scroll, false),
        SideTab::Output => (
            app.output_lines.iter().cloned().map(Line::from).collect(),
            app.side_scroll,
            true,
        ),
    };
    let para = Paragraph::new(lines).scroll((scroll, 0));
    let para = if wrap { para.wrap(Wrap { trim: false }) } else { para };
    frame.render_widget(para, body);
}

fn tab_title(t: SideTab) -> &'static str {
    match t {
        SideTab::Marks => "Marks",
        SideTab::Template => "Template",
        SideTab::Inspect => "Inspect",
        SideTab::Strings => "Strings",
        SideTab::Analysis => "Analysis",
        SideTab::Entropy => "Entropy",
        SideTab::Output => "Output",
    }
}

/// A single-row tab strip that scrolls to keep the selected tab centred,
/// clamped at both ends (no wrap-around), with `<`/`>` edge indicators.
fn tab_header_line(titles: &[&str], selected: usize, width: u16) -> Line<'static> {
    let dim = Style::default().fg(Color::Gray);
    let hot = Style::default()
        .bg(Color::Yellow)
        .fg(Color::Black)
        .add_modifier(Modifier::BOLD);
    let arrow = Style::default().fg(Color::Yellow);

    // Flatten the whole strip into styled characters, tracking the selection.
    let mut chars: Vec<(char, Style)> = Vec::new();
    let (mut sel_start, mut sel_len) = (0usize, 0usize);
    for (i, t) in titles.iter().enumerate() {
        let label = format!(" {t} ");
        if i == selected {
            sel_start = chars.len();
            sel_len = label.chars().count();
        }
        let style = if i == selected { hot } else { dim };
        for c in label.chars() {
            chars.push((c, style));
        }
    }

    let total = chars.len();
    let content_w = (width as usize).saturating_sub(2).max(1); // edges hold arrows
    let scroll = if total <= content_w {
        0
    } else {
        let center = sel_start + sel_len / 2;
        center
            .saturating_sub(content_w / 2)
            .min(total - content_w)
    };
    let left = scroll > 0;
    let right = scroll + content_w < total;

    let mut spans = vec![Span::styled(if left { "<" } else { " " }.to_string(), arrow)];
    for &(c, st) in chars.iter().skip(scroll).take(content_w) {
        spans.push(Span::styled(c.to_string(), st));
    }
    spans.push(Span::styled(if right { ">" } else { " " }.to_string(), arrow));
    Line::from(spans)
}

fn template_lines(app: &App) -> Vec<Line<'static>> {
    let desc = app.template.describe();
    if desc.is_empty() {
        return vec![
            Line::from("no .bxs template loaded"),
            Line::from(""),
            Line::from("auto-loads <file>.bxs, or :loadstructs <file>"),
            Line::from("then :applystruct <name> at the cursor"),
        ];
    }
    desc.into_iter()
        .map(|s| {
            // Definition headers (struct/enum/bitfield/}) start in column 0.
            let header = s
                .starts_with("struct ")
                || s.starts_with("enum ")
                || s.starts_with("bitfield ")
                || s == "}";
            let style = if header {
                Style::default()
                    .fg(app.config.color_annotation)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            Line::from(Span::styled(s, style))
        })
        .collect()
}

fn marks_lines(app: &App, body: Rect) -> Vec<Line<'static>> {
    if app.annotations.is_empty() {
        return vec![
            Line::from("no annotations"),
            Line::from(""),
            Line::from(":mark <start> <end> <label> <type>"),
            Line::from("or select with v then press m"),
            Line::from(":applystruct <name> to parse a struct"),
        ];
    }
    let forest = crate::marks::build(&app.annotations);
    let mut rows: Vec<Line<'static>> = Vec::new();
    render_nodes(&forest, 0, app, &mut rows);

    // Window the (possibly long, when expanded) list to what fits.
    let height = (body.height as usize).max(1);
    let start = (app.side_scroll as usize).min(rows.len().saturating_sub(1));
    rows.into_iter().skip(start).take(height).collect()
}

fn render_nodes(
    level: &[crate::marks::MarkNode],
    depth: usize,
    app: &App,
    out: &mut Vec<Line<'static>>,
) {
    let indent = "  ".repeat(depth);
    for n in level {
        let here = app.cursor >= n.start && app.cursor < n.end;
        if n.is_group() {
            let collapsed = app.collapsed.contains(&n.path);
            // Highlight a collapsed group that holds the cursor (deepest visible).
            let hl = here && collapsed;
            let glyph = if collapsed { "▸" } else { "▾" };
            let name_style = base_style(app, hl);
            out.push(Line::from(vec![
                Span::styled(format!("{indent}{glyph} "), Style::default().fg(Color::DarkGray)),
                Span::styled(format!("{} ", n.name), name_style),
                Span::styled(n.summary(), Style::default().fg(Color::DarkGray)),
            ]));
            if !collapsed {
                render_nodes(&n.children, depth + 1, app, out);
            }
        } else if let Some(ri) = n.region {
            let r = &app.annotations[ri];
            let mut spans = vec![
                Span::styled(format!("{indent}  "), Style::default()),
                Span::styled(format!("{} ", n.name), base_style(app, here)),
                Span::raw(format!("= {}", r.decode(&app.buf))),
            ];
            if let Some(note) = &r.note {
                spans.push(Span::styled(
                    format!("  {note}"),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ));
            }
            out.push(Line::from(spans));
        }
    }
}

fn base_style(app: &App, highlight: bool) -> Style {
    let s = Style::default().fg(app.config.color_annotation);
    if highlight {
        s.add_modifier(Modifier::BOLD | Modifier::REVERSED)
    } else {
        s
    }
}

fn inspect_lines(app: &App) -> Vec<Line<'static>> {
    inspector::lines(&app.buf, app.cursor)
        .into_iter()
        .map(|(label, value)| {
            Line::from(vec![
                Span::styled(format!("{label:<11}"), Style::default().fg(Color::DarkGray)),
                Span::styled(value, Style::default().fg(app.config.color_annotation)),
            ])
        })
        .collect()
}

fn strings_lines(app: &mut App, body: Rect) -> Vec<Line<'static>> {
    app.ensure_strings();
    let cursor = app.cursor;
    let offset_w = format!("{:X}", app.buf.len().max(0x100)).len().max(8);
    let q = app.strings_filter.to_lowercase();
    let (list, trunc) = app.strings_cache.as_ref().unwrap();

    // Apply the live filter (substring, case-insensitive).
    let filtered: Vec<&(u64, String)> = if q.is_empty() {
        list.iter().collect()
    } else {
        list.iter()
            .filter(|(_, s)| s.to_lowercase().contains(&q))
            .collect()
    };

    let mut lines: Vec<Line<'static>> = Vec::new();
    if !app.strings_filter.is_empty() {
        lines.push(Line::from(vec![
            Span::styled("filter ", Style::default().fg(Color::DarkGray)),
            Span::styled(
                app.strings_filter.clone(),
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("  ({} match)", filtered.len()),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
    }
    if filtered.is_empty() {
        lines.push(Line::from(if app.strings_filter.is_empty() {
            format!("no strings ≥{} bytes  ( :strings <min> [utf16] )", app.strings_min)
        } else {
            "no matches  (\\ to edit, Esc to clear)".to_string()
        }));
        return lines;
    }

    let textw = (body.width as usize).saturating_sub(offset_w + 3).max(8);
    let height = (body.height as usize).saturating_sub(lines.len()).max(1);
    let near = filtered.iter().rposition(|(o, _)| *o <= cursor).unwrap_or(0);
    let start = (app.side_scroll as usize).min(filtered.len().saturating_sub(1));

    for (i, (off, s)) in filtered.iter().enumerate().skip(start).take(height) {
        let shown: String = s.chars().take(textw).collect();
        let text_style = if i == near {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(app.config.color_annotation)
        };
        lines.push(Line::from(vec![
            Span::styled(
                format!("{off:0offset_w$X}  "),
                Style::default().fg(Color::DarkGray),
            ),
            Span::styled(shown, text_style),
        ]));
    }
    if *trunc && q.is_empty() {
        lines.push(Line::from(Span::styled(
            format!("… truncated at {}", strings::MAX_STRINGS),
            Style::default().fg(Color::DarkGray),
        )));
    }
    lines
}

fn entropy_lines(app: &mut App, body: Rect) -> Vec<Line<'static>> {
    let buckets = body.height.max(1) as usize;
    // Cache: the whole-file pass is too expensive to redo every keystroke.
    let recompute = app
        .entropy_cache
        .as_ref()
        .is_none_or(|(b, _)| *b != buckets);
    if recompute {
        let computed = entropy::bucketed(app.buf.raw(), buckets);
        app.entropy_cache = Some((buckets, computed));
    }
    let (_, rows) = app.entropy_cache.as_ref().unwrap();
    let offset_w = format!("{:X}", app.buf.len().max(0x100)).len().max(8);
    let bar_w = (body.width as usize).saturating_sub(offset_w + 8).max(4);
    const PARTIAL: [char; 8] = ['▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];
    let cursor_bucket = rows
        .iter()
        .rposition(|&(off, _)| app.cursor >= off)
        .unwrap_or(0);
    rows.iter()
        .enumerate()
        .map(|(i, &(off, h))| {
            let filled = h / 8.0 * bar_w as f64;
            let full = filled as usize;
            let frac = ((filled - full as f64) * 8.0) as usize;
            let mut bar = "█".repeat(full.min(bar_w));
            if full < bar_w && frac > 0 {
                bar.push(PARTIAL[frac.min(7)]);
            }
            let style = if i == cursor_bucket {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else if h > 7.2 {
                Style::default().fg(Color::Red) // likely compressed/encrypted
            } else {
                Style::default().fg(Color::Green)
            };
            Line::from(vec![
                Span::styled(
                    format!("{off:0offset_w$X} "),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(bar, style),
                Span::raw(format!(" {h:.2}")),
            ])
        })
        .collect()
}
