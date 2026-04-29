// chat4000
// Copyright (C) 2026 NeonNode Limited
// Licensed under GPL-3.0. See LICENSE file for details.

use std::io::{self, Write};

use anyhow::Result;
use crossterm::{
    execute,
    style::{Attribute, Color, Print, ResetColor, SetAttribute, SetForegroundColor},
};

const OPTIONS: &[(&str, (u8, u8, u8), (u8, u8, u8), (u8, u8, u8))] = &[
    ("001", (196, 144, 54), (160, 118, 44), (236, 191, 95)),
    ("002", (214, 122, 62), (176, 96, 48), (244, 170, 98)),
    ("003", (204, 110, 92), (166, 84, 74), (237, 155, 136)),
    ("004", (194, 94, 120), (156, 72, 96), (231, 138, 165)),
    ("005", (180, 92, 160), (142, 71, 127), (220, 140, 201)),
    ("006", (158, 104, 196), (124, 82, 158), (201, 150, 236)),
    ("007", (132, 122, 208), (103, 95, 169), (176, 169, 241)),
    ("008", (100, 140, 214), (78, 110, 175), (145, 186, 243)),
    ("009", (76, 156, 214), (59, 122, 173), (126, 198, 243)),
    ("010", (64, 170, 206), (50, 132, 166), (117, 211, 237)),
    ("011", (56, 180, 190), (44, 140, 151), (113, 221, 222)),
    ("012", (60, 178, 164), (47, 140, 129), (116, 220, 200)),
    ("013", (76, 170, 144), (59, 134, 113), (128, 212, 179)),
    ("014", (92, 162, 124), (73, 129, 98), (142, 205, 159)),
    ("015", (116, 156, 102), (92, 123, 81), (165, 200, 137)),
    ("016", (144, 150, 84), (114, 118, 66), (191, 194, 122)),
    ("017", (170, 145, 74), (136, 116, 58), (214, 189, 111)),
    ("018", (192, 138, 66), (154, 110, 52), (232, 182, 102)),
    ("019", (204, 132, 82), (164, 105, 65), (238, 177, 120)),
    ("020", (88, 207, 177), (67, 159, 138), (152, 235, 214)),
];

const SPINNER_FRAMES: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

fn main() -> Result<()> {
    let mut stdout = io::stdout();
    execute!(
        stdout,
        SetAttribute(Attribute::Bold),
        Print("Status Prefix Color Preview\n"),
        SetAttribute(Attribute::Reset),
        Print("Pick the option number you want.\n\n")
    )?;

    for (option, base, soft, shimmer) in OPTIONS {
        let prefix = format_status_prefix(SPINNER_FRAMES[0], "Typing", 17);
        let draft = "A plain live draft stays uncolored.";
        execute!(
            stdout,
            Print(format!("{option}  ")),
            SetForegroundColor(rgb(*base)),
            Print(render_prefix_sample(
                &prefix,
                rgb(*base),
                rgb(*soft),
                rgb(*shimmer)
            )),
            ResetColor,
            Print(draft),
            Print("\n")
        )?;
    }

    stdout.flush()?;
    Ok(())
}

fn format_status_prefix(spinner: &str, label: &str, secs: u64) -> String {
    let timer = format!("{secs}s");
    format!("{}{:>4} {:<7} ", spinner, timer, label)
}

fn render_prefix_sample(prefix: &str, base: Color, soft: Color, shimmer: Color) -> String {
    let chars: Vec<char> = prefix.chars().collect();
    let glimmer_index = chars.len() / 2;
    let mut out = String::new();
    for (index, ch) in chars.iter().enumerate() {
        let color = if index == glimmer_index {
            shimmer
        } else if index.abs_diff(glimmer_index) == 1 {
            soft
        } else {
            base
        };
        out.push_str(&ansi_fg(color));
        out.push(*ch);
    }
    out.push_str("\x1b[0m");
    out
}

fn rgb((r, g, b): (u8, u8, u8)) -> Color {
    Color::Rgb { r, g, b }
}

fn ansi_fg(color: Color) -> String {
    match color {
        Color::Rgb { r, g, b } => format!("\x1b[38;2;{r};{g};{b}m"),
        _ => "\x1b[39m".to_string(),
    }
}
