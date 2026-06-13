//! Root layout: hex pane(s) + annotation/analysis side pane + info bar.

mod annopane;
mod hexview;
mod infobar;

use ratatui::Frame;
use ratatui::layout::{Constraint, Layout};

use crate::app::App;
use crate::config::AnnoPanePos;

pub fn draw(frame: &mut Frame, app: &mut App) {
    let [main, info] =
        Layout::vertical([Constraint::Min(3), Constraint::Length(2)]).areas(frame.area());

    let pane = app.config.anno_pane;
    let want_side = pane != AnnoPanePos::Off && main.width > app.config.anno_width + 40;
    let (hex_area, side_area) = if want_side {
        let w = app.config.anno_width;
        match pane {
            AnnoPanePos::Right => {
                let [h, s] =
                    Layout::horizontal([Constraint::Min(20), Constraint::Length(w)]).areas(main);
                (h, Some(s))
            }
            _ => {
                let [s, h] =
                    Layout::horizontal([Constraint::Length(w), Constraint::Min(20)]).areas(main);
                (h, Some(s))
            }
        }
    } else {
        (main, None)
    };

    app.view_rows = hex_area.height.saturating_sub(2).max(1) as usize;

    if app.diff_buf.is_some() {
        let [left, right] =
            Layout::horizontal([Constraint::Percentage(50), Constraint::Percentage(50)])
                .areas(hex_area);
        hexview::render(frame, left, app, hexview::Side::Main);
        hexview::render(frame, right, app, hexview::Side::DiffRight);
    } else {
        hexview::render(frame, hex_area, app, hexview::Side::Main);
    }

    if let Some(side) = side_area {
        annopane::render(frame, side, app);
    }

    infobar::render(frame, info, app);
}
