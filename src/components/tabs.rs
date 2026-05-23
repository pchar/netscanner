use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use crossterm::event::{KeyCode, KeyEvent};
use ratatui::style::Stylize;
use ratatui::{prelude::*, widgets::*};
use ratatui::{
    text::{Line, Span},
    widgets::{block::Title, Paragraph},
};
use serde::{Deserialize, Serialize};
use strum::{EnumCount, IntoEnumIterator};
use tokio::sync::mpsc::UnboundedSender;

use super::{Component, Frame};
use crate::{
    action::Action,
    config::DEFAULT_BORDER_STYLE,
    config::{Config, KeyBindings},
    enums::TabsEnum,
    layout::get_vertical_layout,
};

#[derive(Default)]
pub struct Tabs {
    action_tx: Option<UnboundedSender<Action>>,
    config: Config,
    tab_index: usize,
}

impl Tabs {
    pub fn new() -> Self {
        Self {
            action_tx: None,
            config: Config::default(),
            tab_index: 0,
        }
    }

    fn make_tabs(&self) -> Paragraph<'_> {
        // Build tab names with numbers for left side
        let tab_items: Vec<Span> =
            TabsEnum::iter()
                .enumerate()
                .fold(Vec::new(), |mut spans, (idx, p)| {
                    let index_str = idx + 1;
                    let tab_style = if idx == self.tab_index {
                        Style::default().green().bold()
                    } else {
                        Style::default().dark_gray().bold()
                    };
                    spans.extend_from_slice(&[
                        Span::styled("(", Style::default().fg(Color::Yellow)),
                        Span::styled(format!("{}", index_str), Style::default().fg(Color::Red)),
                        Span::styled(")", Style::default().fg(Color::Yellow)),
                        Span::styled(p.to_string(), tab_style),
                        Span::raw("  "),
                    ]);
                    spans
                });

        // Build right-side action keys based on current tab
        let action_items: Vec<Span> = match TabsEnum::iter().nth(self.tab_index).unwrap() {
            TabsEnum::Discovery => vec![
                Span::styled("|", Style::default().fg(Color::Yellow)),
                Span::styled("s", Style::default().add_modifier(Modifier::BOLD).fg(Color::Red)),
                Span::styled("can ", Style::default().fg(Color::Yellow)),
                Span::styled("stop", Style::default().fg(Color::Yellow)),
                Span::styled(" ", Style::default().fg(Color::Yellow)),
                Span::styled("e", Style::default().add_modifier(Modifier::BOLD).fg(Color::Red)),
                Span::styled("xport", Style::default().fg(Color::Yellow)),
                Span::styled("|", Style::default().fg(Color::Yellow)),
            ],
            TabsEnum::Packets => vec![
                Span::styled("|", Style::default().fg(Color::Yellow)),
                Span::styled("d", Style::default().add_modifier(Modifier::BOLD).fg(Color::Red)),
                Span::styled("ump ", Style::default().fg(Color::Yellow)),
                Span::styled("s", Style::default().add_modifier(Modifier::BOLD).fg(Color::Red)),
                Span::styled("top", Style::default().fg(Color::Yellow)),
                Span::styled("|", Style::default().fg(Color::Yellow)),
            ],
            TabsEnum::Traffic => vec![
                Span::styled("|", Style::default().fg(Color::Yellow)),
                Span::styled("d", Style::default().add_modifier(Modifier::BOLD).fg(Color::Red)),
                Span::styled("ump ", Style::default().fg(Color::Yellow)),
                Span::styled("s", Style::default().add_modifier(Modifier::BOLD).fg(Color::Red)),
                Span::styled("top", Style::default().fg(Color::Yellow)),
                Span::styled("|", Style::default().fg(Color::Yellow)),
            ],
            TabsEnum::Ports => vec![
                Span::styled("|", Style::default().fg(Color::Yellow)),
                Span::styled("s", Style::default().add_modifier(Modifier::BOLD).fg(Color::Red)),
                Span::styled("can ", Style::default().fg(Color::Yellow)),
                Span::styled("s", Style::default().add_modifier(Modifier::BOLD).fg(Color::Red)),
                Span::styled("top", Style::default().fg(Color::Yellow)),
                Span::styled("|", Style::default().fg(Color::Yellow)),
            ],
        };

        // Two separate rows in the block
        let b = Block::default()
            .title(
                Title::from(Line::from(tab_items.clone()))
                    .alignment(Alignment::Left)
                    .position(block::Position::Top),
            )
            .title(
                Title::from(Line::from(action_items.clone()))
                    .alignment(Alignment::Right)
                    .position(block::Position::Bottom),
            )
            .borders(Borders::ALL)
            .border_type(DEFAULT_BORDER_STYLE)
            .padding(Padding::new(0, 0, 0, 0))
            .border_style(Style::default().fg(Color::Rgb(100, 100, 100)));

        // Content is just the tab names (for internal rendering)
        let content = Line::from(tab_items);
        Paragraph::new(content).block(b)
    }

    fn next_tab(&mut self) {
        self.tab_index = (self.tab_index + 1) % TabsEnum::COUNT;
        if let Some(ref action_tx) = self.action_tx {
            let tab_enum = TabsEnum::iter().nth(self.tab_index).unwrap();
            action_tx.send(Action::TabChange(tab_enum)).unwrap();
        }
    }
}

impl Component for Tabs {
    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn register_config_handler(&mut self, config: Config) -> Result<()> {
        self.config = config;
        Ok(())
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        match action {
            Action::Tab => {
                self.next_tab();
            }

            Action::TabChange(tab_enum) => TabsEnum::iter().enumerate().for_each(|(idx, t)| {
                if tab_enum == t {
                    self.tab_index = idx;
                }
            }),

            _ => {}
        }
        Ok(None)
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        let layout = get_vertical_layout(area);
        let mut rect = layout.tabs;
        rect.y += 1;

        let tabs = self.make_tabs();
        f.render_widget(tabs, rect);

        Ok(())
    }
}
