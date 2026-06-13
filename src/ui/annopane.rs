//! Side pane: tabbed Marks / Analysis / Entropy / Output views.

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Tabs, Wrap};

use crate::analysis::entropy;
use crate::app::{App, SideTab};
use crate::inspector;

pub fn render(frame: &mut Frame, area: Rect, app: &mut App) {
    let block = Block::bordered();
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let [tab_area, body] =
        Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);

    let titles = ["Marks", "Inspect", "Analysis", "Entropy", "Output"];
    let selected = match app.side_tab {
        SideTab::Marks => 0,
        SideTab::Inspect => 1,
        SideTab::Analysis => 2,
        SideTab::Entropy => 3,
        SideTab::Output => 4,
    };
    let tabs = Tabs::new(titles.iter().map(|t| Line::from(*t)))
        .select(selected)
        .highlight_style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        );
    frame.render_widget(tabs, tab_area);

    let lines: Vec<Line> = match app.side_tab {
        SideTab::Marks => marks_lines(app),
        SideTab::Inspect => inspect_lines(app),
        SideTab::Analysis => app.info_lines().into_iter().map(Line::from).collect(),
        SideTab::Entropy => entropy_lines(app, body),
        SideTab::Output => app.output_lines.iter().cloned().map(Line::from).collect(),
    };
    frame.render_widget(
        Paragraph::new(lines)
            .scroll((app.side_scroll, 0))
            .wrap(Wrap { trim: false }),
        body,
    );
}

fn marks_lines(app: &App) -> Vec<Line<'static>> {
    if app.annotations.is_empty() {
        return vec![
            Line::from("no annotations"),
            Line::from(""),
            Line::from(":mark <start> <end> <label> <type>"),
            Line::from("or select with v then press m"),
        ];
    }
    let mut lines = Vec::new();
    for r in &app.annotations {
        let here = r.contains(app.cursor);
        let head_style = if here {
            Style::default()
                .fg(app.config.color_annotation)
                .add_modifier(Modifier::BOLD | Modifier::REVERSED)
        } else {
            Style::default().fg(app.config.color_annotation)
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{} ", r.label), head_style),
            Span::styled(
                format!("{} 0x{:X}..0x{:X}", r.rtype, r.start, r.end),
                Style::default().fg(Color::DarkGray),
            ),
        ]));
        lines.push(Line::from(format!("  = {}", r.decode(&app.buf))));
    }
    lines
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
