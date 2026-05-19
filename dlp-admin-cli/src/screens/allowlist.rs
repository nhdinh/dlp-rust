//! Admin TUI allowlist configuration screen.
//!
//! Navigable list of allowlist entries with add/edit/disable actions.

use crossterm::event::{KeyCode, KeyEvent};
use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Style},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
    Frame,
};

/// Action returned from key handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowlistAction {
    GoBack,
}

/// Screen state for allowlist management.
#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct AllowlistScreen {
    /// Entries loaded from the server.
    pub entries: Vec<AllowlistEntryUi>,
    /// Currently selected row index.
    pub selected: usize,
    /// Current interaction mode.
    pub mode: AllowlistMode,
    /// Buffer for text input during edit/add.
    pub edit_buffer: String,
    /// Current field being edited (0..=4 for add/edit form).
    pub edit_field: usize,
    /// Error message to display.
    pub error_message: Option<String>,
    /// Whether a refresh is pending (triggers server fetch on next render).
    pub refresh_pending: bool,
}

/// UI representation of a single allowlist entry.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct AllowlistEntryUi {
    /// Server-generated UUID.
    pub id: String,
    /// Match type string.
    pub match_type: String,
    /// Match value.
    pub value: String,
    /// Human-readable description.
    pub description: String,
    /// Category string.
    pub category: String,
    /// Priority (lower = higher).
    pub priority: i64,
    /// Enabled flag.
    pub enabled: bool,
}

/// Interaction modes for the allowlist screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowlistMode {
    /// List view — navigate entries.
    List,
    /// Add new entry — multi-field form.
    Add,
    /// Edit existing entry — multi-field form.
    Edit,
    /// Confirm disable action.
    ConfirmDisable,
    /// Confirm delete action.
    ConfirmDelete,
}

impl Default for AllowlistScreen {
    fn default() -> Self {
        Self::new()
    }
}

impl AllowlistScreen {
    /// Creates a new empty allowlist screen.
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            selected: 0,
            mode: AllowlistMode::List,
            edit_buffer: String::new(),
            edit_field: 0,
            error_message: None,
            refresh_pending: true,
        }
    }

    /// Handles a key event based on current mode.
    pub fn handle_key(
        &mut self,
        key: KeyEvent,
        _client: &mut crate::client::EngineClient,
    ) -> Option<AllowlistAction> {
        match self.mode {
            AllowlistMode::List => self.handle_list_mode(key),
            AllowlistMode::Add | AllowlistMode::Edit => self.handle_edit_mode(key),
            AllowlistMode::ConfirmDisable | AllowlistMode::ConfirmDelete => {
                self.handle_confirm_mode(key)
            }
        }
    }

    fn handle_list_mode(&mut self, key: KeyEvent) -> Option<AllowlistAction> {
        match key.code {
            KeyCode::Up => {
                if self.selected > 0 {
                    self.selected -= 1;
                }
            }
            KeyCode::Down => {
                if self.selected + 1 < self.entries.len() {
                    self.selected += 1;
                }
            }
            KeyCode::Char('a') => {
                self.mode = AllowlistMode::Add;
                self.edit_buffer.clear();
                self.edit_field = 0;
            }
            KeyCode::Char('e') => {
                if !self.entries.is_empty() {
                    self.mode = AllowlistMode::Edit;
                    self.edit_buffer = self.entries[self.selected].value.clone();
                    self.edit_field = 0;
                }
            }
            KeyCode::Char('d') => {
                if !self.entries.is_empty() {
                    self.mode = AllowlistMode::ConfirmDisable;
                }
            }
            KeyCode::Char('x') => {
                if !self.entries.is_empty() {
                    self.mode = AllowlistMode::ConfirmDelete;
                }
            }
            KeyCode::F(5) => {
                // Manual refresh trigger.
                self.refresh_pending = true;
            }
            KeyCode::Esc => {
                return Some(AllowlistAction::GoBack);
            }
            _ => {}
        }
        None
    }

    fn handle_edit_mode(&mut self, key: KeyEvent) -> Option<AllowlistAction> {
        match key.code {
            KeyCode::Enter => {
                // Submit edit/add and return to list.
                self.mode = AllowlistMode::List;
                self.refresh_pending = true;
            }
            KeyCode::Esc => {
                self.mode = AllowlistMode::List;
            }
            KeyCode::Char(c) => {
                self.edit_buffer.push(c);
            }
            KeyCode::Backspace => {
                self.edit_buffer.pop();
            }
            _ => {}
        }
        None
    }

    fn handle_confirm_mode(&mut self, key: KeyEvent) -> Option<AllowlistAction> {
        match key.code {
            KeyCode::Char('y') => {
                // Confirm disable/delete.
                self.mode = AllowlistMode::List;
                self.refresh_pending = true;
            }
            KeyCode::Char('n') | KeyCode::Esc => {
                self.mode = AllowlistMode::List;
            }
            _ => {}
        }
        None
    }
}

/// Renders the allowlist screen.
pub fn draw_allowlist_screen(frame: &mut Frame, screen: &AllowlistScreen, area: Rect) {
    let block = Block::default()
        .title("Allowlist Configuration (F5=Refresh, a=Add, e=Edit, d=Disable, x=Delete, Esc=Back)")
        .borders(Borders::ALL);

    let items: Vec<ListItem> = screen
        .entries
        .iter()
        .enumerate()
        .map(|(i, entry)| {
            let style = if i == screen.selected {
                Style::default().fg(Color::Black).bg(Color::White)
            } else if !entry.enabled {
                Style::default().fg(Color::DarkGray)
            } else {
                Style::default()
            };
            let status = if entry.enabled { "[+]" } else { "[-]" };
            ListItem::new(format!(
                "{} {} | {} | {} | {}",
                status, entry.match_type, entry.value, entry.category, entry.description
            ))
            .style(style)
        })
        .collect();

    let list = List::new(items).block(block);
    frame.render_widget(list, area);

    // Render confirmation modal if in confirm mode.
    match screen.mode {
        AllowlistMode::ConfirmDisable | AllowlistMode::ConfirmDelete => {
            let message = if screen.mode == AllowlistMode::ConfirmDisable {
                "Disable this entry? (y/n)"
            } else {
                "Delete this entry? (y/n)"
            };
            draw_confirm_modal(frame, message, area);
        }
        _ => {}
    }
}

/// Draws a centered confirmation modal.
fn draw_confirm_modal(frame: &mut Frame, message: &str, area: Rect) {
    let popup_area = centered_rect(40, 20, area);
    frame.render_widget(Clear, popup_area);

    let block = Block::default()
        .title("Confirm")
        .borders(Borders::ALL)
        .style(Style::default().bg(Color::Black));

    let text = Paragraph::new(message)
        .block(block)
        .wrap(Wrap { trim: true });
    frame.render_widget(text, popup_area);
}

/// Computes a centered rectangle of given percentage size.
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allowlist_screen_new() {
        let screen = AllowlistScreen::new();
        assert!(screen.entries.is_empty());
        assert_eq!(screen.selected, 0);
        assert_eq!(screen.mode, AllowlistMode::List);
        assert!(screen.refresh_pending);
    }

    #[test]
    fn test_allowlist_screen_navigation() {
        let mut screen = AllowlistScreen {
            entries: vec![
                AllowlistEntryUi {
                    id: "1".to_string(),
                    match_type: "exact_path".to_string(),
                    value: r"C:\test.exe".to_string(),
                    description: "Test".to_string(),
                    category: "operator_defined".to_string(),
                    priority: 10,
                    enabled: true,
                },
                AllowlistEntryUi {
                    id: "2".to_string(),
                    match_type: "cert_subject".to_string(),
                    value: "O=CrowdStrike".to_string(),
                    description: "AV".to_string(),
                    category: "avedr".to_string(),
                    priority: 5,
                    enabled: true,
                },
            ],
            selected: 0,
            mode: AllowlistMode::List,
            edit_buffer: String::new(),
            edit_field: 0,
            error_message: None,
            refresh_pending: false,
        };

        // Down moves selection.
        let result = screen.handle_list_mode(KeyEvent::from(KeyCode::Down));
        assert!(result.is_none());
        assert_eq!(screen.selected, 1);

        // Up moves selection back.
        let result = screen.handle_list_mode(KeyEvent::from(KeyCode::Up));
        assert!(result.is_none());
        assert_eq!(screen.selected, 0);
    }

    #[test]
    fn test_allowlist_mode_transitions() {
        let mut screen = AllowlistScreen {
            entries: vec![AllowlistEntryUi {
                id: "1".to_string(),
                match_type: "exact_path".to_string(),
                value: r"C:\test.exe".to_string(),
                description: "Test".to_string(),
                category: "operator_defined".to_string(),
                priority: 10,
                enabled: true,
            }],
            selected: 0,
            mode: AllowlistMode::List,
            edit_buffer: String::new(),
            edit_field: 0,
            error_message: None,
            refresh_pending: false,
        };

        // 'a' enters Add mode.
        screen.handle_list_mode(KeyEvent::from(KeyCode::Char('a')));
        assert_eq!(screen.mode, AllowlistMode::Add);

        // Esc returns to List.
        screen.handle_edit_mode(KeyEvent::from(KeyCode::Esc));
        assert_eq!(screen.mode, AllowlistMode::List);

        // 'e' enters Edit mode.
        screen.handle_list_mode(KeyEvent::from(KeyCode::Char('e')));
        assert_eq!(screen.mode, AllowlistMode::Edit);

        // Esc returns to List.
        screen.handle_edit_mode(KeyEvent::from(KeyCode::Esc));
        assert_eq!(screen.mode, AllowlistMode::List);

        // 'd' enters ConfirmDisable mode.
        screen.handle_list_mode(KeyEvent::from(KeyCode::Char('d')));
        assert_eq!(screen.mode, AllowlistMode::ConfirmDisable);

        // 'n' cancels.
        screen.handle_confirm_mode(KeyEvent::from(KeyCode::Char('n')));
        assert_eq!(screen.mode, AllowlistMode::List);

        // 'x' enters ConfirmDelete mode.
        screen.handle_list_mode(KeyEvent::from(KeyCode::Char('x')));
        assert_eq!(screen.mode, AllowlistMode::ConfirmDelete);

        // 'y' confirms.
        screen.handle_confirm_mode(KeyEvent::from(KeyCode::Char('y')));
        assert_eq!(screen.mode, AllowlistMode::List);
        assert!(screen.refresh_pending);
    }

    #[test]
    fn test_f5_triggers_refresh() {
        let mut screen = AllowlistScreen::new();
        screen.refresh_pending = false;
        screen.handle_list_mode(KeyEvent::from(KeyCode::F(5)));
        assert!(screen.refresh_pending);
    }

    #[test]
    fn test_esc_pops_screen() {
        let mut screen = AllowlistScreen::new();
        let result = screen.handle_list_mode(KeyEvent::from(KeyCode::Esc));
        assert!(matches!(result, Some(AllowlistAction::GoBack)));
    }
}
