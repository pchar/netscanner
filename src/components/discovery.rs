use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;

use pnet::datalink::NetworkInterface;

use ratatui::layout::Position;
use ratatui::{prelude::*, widgets::*};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::time::Duration;
use tokio::sync::mpsc::UnboundedSender;

use super::Component;
use crate::{
    action::Action,
    components::packetdump::ArpPacketData,
    config::DEFAULT_BORDER_STYLE,
    enums::TabsEnum,
    layout::get_vertical_layout,
    mode::Mode,
    tui::Frame,
    utils::{count_ipv4_net_length, get_ips4_from_cidr},
};
use crossterm::event::Event;
use crossterm::event::{KeyCode, KeyEvent};
use mac_oui::Oui;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

static POOL_SIZE: usize = 32;
static INPUT_SIZE: usize = 30;
static DEFAULT_IP: &str = "192.168.1.0/24";
const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

// ---------------------------------------------------------------------------
// Shell-based helpers — no root/sudo required.
// ---------------------------------------------------------------------------

/// Ping a host once using the system `ping`. Returns true if it responds.
fn ping_host(ip: &str) -> bool {
    #[cfg(target_os = "macos")]
    let args: &[&str] = &["-c", "1", "-t", "1", ip];
    #[cfg(not(target_os = "macos"))]
    let args: &[&str] = &["-c", "1", "-W", "1", ip];

    std::process::Command::new("ping")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Reverse-DNS via `dig`, falling back to `nslookup`.
fn resolve_hostname(ip: &str) -> String {
    if let Ok(out) = std::process::Command::new("dig")
        .args(["-x", ip, "+short", "+time=2", "+tries=1"])
        .output()
    {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            let h = line.trim().trim_end_matches('.');
            if !h.is_empty() && !h.starts_with(";;") {
                return h.to_string();
            }
        }
    }
    if let Ok(out) = std::process::Command::new("nslookup").arg(ip).output() {
        let s = String::from_utf8_lossy(&out.stdout);
        for line in s.lines() {
            if let Some(pos) = line.find("name = ") {
                return line[pos + 7..].trim().trim_end_matches('.').to_string();
            }
        }
    }
    String::new()
}

/// Read MAC from the OS ARP cache. Ping the host first to populate it.
fn get_mac(ip: &str) -> String {
    let out = match std::process::Command::new("arp").args(["-n", ip]).output() {
        Ok(o) => String::from_utf8_lossy(&o.stdout).to_string(),
        Err(_) => return String::new(),
    };
    for token in out.split_whitespace() {
        if token.len() >= 11 && (token.contains(':') || token.contains('-')) {
            if token
                .chars()
                .all(|c| c.is_ascii_hexdigit() || c == ':' || c == '-')
            {
                return token.replace('-', ":");
            }
        }
    }
    String::new()
}

// ---------------------------------------------------------------------------
// Thread-pool scanner with coordinator
//
// Layout:
//   start() fills a shared work queue with all IPs, then spawns `pool_size`
//   worker threads. Each worker pulls IPs from the queue, pings them, and
//   reports live ones via the action channel. A coordinator thread blocks
//   until every worker exits, then sends ScanComplete.
//
// stop() sets a flag that workers check between steps; they exit cleanly
// within at most one ping-timeout (1 second) of the flag being set.
// ---------------------------------------------------------------------------

struct Scanner {
    stop_flag: Arc<AtomicBool>,
    coordinator: Option<std::thread::JoinHandle<()>>,
}

impl Scanner {
    fn new() -> Self {
        Self {
            stop_flag: Arc::new(AtomicBool::new(false)),
            coordinator: None,
        }
    }

    fn start(
        &mut self,
        ips: Vec<Ipv4Addr>,
        action_tx: UnboundedSender<Action>,
        pool_size: usize,
    ) {
        self.stop_flag.store(false, Ordering::SeqCst);
        let stop_flag = self.stop_flag.clone();

        let total = ips.len();
        if total == 0 {
            action_tx.send(Action::ScanComplete).ok();
            return;
        }

        // Shared work queue — workers pull IPs from here.
        let (work_tx, work_rx) = std::sync::mpsc::channel::<String>();
        let work_rx = Arc::new(Mutex::new(work_rx));
        for ip in ips {
            work_tx.send(ip.to_string()).ok();
        }
        drop(work_tx); // closes queue; workers see Err when it empties

        // Each worker clones done_tx. When the last clone drops, done_rx
        // unblocks and the coordinator knows all workers have exited.
        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();

        let actual_pool = pool_size.min(total);
        for _ in 0..actual_pool {
            let work_rx = work_rx.clone();
            let tx = action_tx.clone();
            let stop = stop_flag.clone();
            let done_tx = done_tx.clone();

            std::thread::spawn(move || {
                loop {
                    // Pull next IP from shared queue.
                    let ip = {
                        let rx = work_rx.lock().unwrap();
                        match rx.recv() {
                            Ok(ip) => ip,
                            Err(_) => break, // queue exhausted
                        }
                    };

                    if stop.load(Ordering::Relaxed) {
                        break;
                    }

                    if ping_host(&ip) {
                        // Report live host immediately so the table updates.
                        tx.send(Action::PingIpResponded(ip.clone())).ok();

                        if !stop.load(Ordering::Relaxed) {
                            let hostname = resolve_hostname(&ip);
                            // Small pause so the OS ARP cache fills after ping.
                            std::thread::sleep(Duration::from_millis(150));
                            let mac = get_mac(&ip);
                            tx.send(Action::IpResolved { ip, hostname, mac }).ok();
                        }
                    }

                    // Always count — drives the progress display.
                    tx.send(Action::CountIp).ok();
                }
                drop(done_tx); // signals this worker is done
            });
        }
        drop(done_tx); // drop original; workers hold all live copies

        // Coordinator: block until every worker exits, then notify the UI.
        let tx = action_tx;
        let coordinator = std::thread::spawn(move || {
            // recv() returns Err only when ALL done_tx clones are dropped.
            let _ = done_rx.recv();
            tx.send(Action::ScanComplete).ok();
        });
        self.coordinator = Some(coordinator);
    }

    fn stop(&self) {
        self.stop_flag.store(true, Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq)]
pub struct ScannedIp {
    pub ip: String,
    pub mac: String,
    pub hostname: String,
    pub vendor: String,
}

pub struct Discovery {
    active_tab: TabsEnum,
    active_interface: Option<NetworkInterface>,
    action_tx: Option<UnboundedSender<Action>>,
    scanned_ips: Vec<ScannedIp>,
    ip_num: i32,
    input: Input,
    cidr: Option<Ipv4Cidr>,
    cidr_error: bool,
    is_scanning: bool,
    mode: Mode,
    scanner: Scanner,
    oui: Option<Oui>,
    table_state: TableState,
    scrollbar_state: ScrollbarState,
    spinner_index: usize,
    sort_column: crate::action::SortColumn,
    showing_sort_menu: bool,
    sort_selected_idx: usize,
}

impl Default for Discovery {
    fn default() -> Self {
        Self::new()
    }
}

impl Discovery {
    pub fn new() -> Self {
        Self {
            active_tab: TabsEnum::Discovery,
            active_interface: None,
            scanner: Scanner::new(),
            action_tx: None,
            scanned_ips: Vec::new(),
            ip_num: 0,
            input: Input::default().with_value(String::from(DEFAULT_IP)),
            cidr: None,
            cidr_error: false,
            is_scanning: false,
            mode: Mode::Normal,
            oui: None,
            table_state: TableState::default().with_selected(0),
            scrollbar_state: ScrollbarState::new(0),
            spinner_index: 0,
            sort_column: crate::action::SortColumn::Ip,
            showing_sort_menu: false,
            sort_selected_idx: 0,
        }
    }

    pub fn get_scanned_ips(&self) -> &Vec<ScannedIp> {
        &self.scanned_ips
    }

    fn sort_scanned_ips(&mut self) {
        match self.sort_column {
            crate::action::SortColumn::Hostname => {
                self.scanned_ips
                    .sort_by(|a, b| a.hostname.to_lowercase().cmp(&b.hostname.to_lowercase()));
            }
            crate::action::SortColumn::Mac => {
                self.scanned_ips
                    .sort_by(|a, b| a.mac.to_lowercase().cmp(&b.mac.to_lowercase()));
            }
            crate::action::SortColumn::Vendor => {
                self.scanned_ips
                    .sort_by(|a, b| a.vendor.to_lowercase().cmp(&b.vendor.to_lowercase()));
            }
            crate::action::SortColumn::Ip => {
                self.scanned_ips.sort_by(|a, b| {
                    let a_ip: Ipv4Addr =
                        a.ip.parse().unwrap_or_else(|_| Ipv4Addr::new(0, 0, 0, 0));
                    let b_ip: Ipv4Addr =
                        b.ip.parse().unwrap_or_else(|_| Ipv4Addr::new(0, 0, 0, 0));
                    a_ip.cmp(&b_ip)
                });
            }
        }
        self.set_scrollbar_height();
    }

    fn set_cidr(&mut self, cidr_str: String, scan: bool) {
        match cidr_str.parse::<Ipv4Cidr>() {
            Ok(ip_cidr) => {
                self.cidr = Some(ip_cidr);
                if scan {
                    self.scan();
                }
            }
            Err(_) => {
                if let Some(tx) = &self.action_tx {
                    tx.clone().send(Action::CidrError).unwrap();
                }
            }
        }
    }

    fn reset_scan(&mut self) {
        self.scanned_ips.clear();
        self.ip_num = 0;
    }

    fn scan(&mut self) {
        self.reset_scan();
        if let Some(cidr) = self.cidr {
            self.is_scanning = true;
            let ips = get_ips4_from_cidr(cidr);
            let tx = self.action_tx.as_ref().unwrap().clone();
            self.scanner.start(ips, tx, POOL_SIZE);
        }
    }

    /// Add a placeholder row immediately when a host responds to ping.
    /// Full details (hostname, MAC) arrive shortly via `IpResolved`.
    fn process_ip(&mut self, ip: &str) {
        if !self.scanned_ips.iter().any(|item| item.ip == ip) {
            self.scanned_ips.push(ScannedIp {
                ip: ip.to_string(),
                mac: String::new(),
                hostname: String::new(),
                vendor: String::new(),
            });
            self.sort_scanned_ips();
            self.set_scrollbar_height();
        }
    }

    /// Update MAC (and vendor) from a passively captured ARP packet.
    fn process_mac(&mut self, arp_data: ArpPacketData) {
        if let Some(n) = self
            .scanned_ips
            .iter_mut()
            .find(|item| item.ip == arp_data.sender_ip.to_string())
        {
            n.mac = arp_data.sender_mac.to_string();
            if let Some(oui) = &self.oui {
                if let Ok(Some(oui_res)) = oui.lookup_by_mac(&n.mac) {
                    n.vendor = oui_res.company_name.clone();
                }
            }
        }
    }

    fn set_active_subnet(&mut self, intf: &NetworkInterface) {
        let ipv4 = intf.ips.iter().find_map(|ip| {
            if let IpAddr::V4(v4) = ip.ip() {
                if v4.is_private() && !v4.is_loopback() && !v4.is_unspecified() {
                    return Some(v4);
                }
            }
            None
        });
        if let Some(ip) = ipv4 {
            let ip_str = ip.to_string();
            let parts: Vec<&str> = ip_str.split('.').collect();
            if parts.len() > 1 {
                let new_a_ip = format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]);
                self.input = Input::default().with_value(new_a_ip);
                self.set_cidr(self.input.value().to_string(), false);
            }
        }
    }

    fn set_scrollbar_height(&mut self) {
        let ip_len = if self.scanned_ips.is_empty() {
            0
        } else {
            self.scanned_ips.len() - 1
        };
        self.scrollbar_state = self.scrollbar_state.content_length(ip_len);
    }

    fn previous_in_table(&mut self) {
        let index = match self.table_state.selected() {
            Some(index) => {
                if index == 0 {
                    if self.scanned_ips.is_empty() {
                        0
                    } else {
                        self.scanned_ips.len() - 1
                    }
                } else {
                    index - 1
                }
            }
            None => 0,
        };
        self.table_state.select(Some(index));
        self.scrollbar_state = self.scrollbar_state.position(index);
    }

    fn next_in_table(&mut self) {
        let index = match self.table_state.selected() {
            Some(index) => {
                let s_ip_len = if self.scanned_ips.is_empty() {
                    0
                } else {
                    self.scanned_ips.len() - 1
                };
                if index >= s_ip_len { 0 } else { index + 1 }
            }
            None => 0,
        };
        self.table_state.select(Some(index));
        self.scrollbar_state = self.scrollbar_state.position(index);
    }

    fn make_table<'a>(
        scanned_ips: &'a Vec<ScannedIp>,
        cidr: Option<Ipv4Cidr>,
        ip_num: i32,
        is_scanning: bool,
        sort_column: &'a crate::action::SortColumn,
    ) -> Table<'a> {
        let header = Row::new(vec!["ip", "mac", "hostname", "vendor"])
            .style(Style::default().fg(Color::Yellow))
            .top_margin(1)
            .bottom_margin(1);
        let mut rows = Vec::new();
        let cidr_length = match cidr {
            Some(c) => count_ipv4_net_length(c.network_length() as u32),
            None => 0,
        };

        for sip in scanned_ips {
            let ip = &sip.ip;
            rows.push(Row::new(vec![
                Cell::from(Span::styled(
                    format!("{ip:<2}"),
                    Style::default().fg(Color::Blue),
                )),
                Cell::from(sip.mac.as_str().green()),
                Cell::from(sip.hostname.as_str()),
                Cell::from(sip.vendor.as_str().yellow()),
            ]));
        }

        let mut scan_title = vec![
            Span::styled("|", Style::default().fg(Color::Yellow)),
            "◉ ".green(),
            Span::styled(
                format!("{}", scanned_ips.len()),
                Style::default().fg(Color::Red),
            ),
            Span::styled("|", Style::default().fg(Color::Yellow)),
        ];
        if is_scanning {
            scan_title.push(" ⣿(".yellow());
            scan_title.push(format!("{}", ip_num).red());
            scan_title.push(format!("/{}", cidr_length).green());
            scan_title.push(")".yellow());
        }

        let mut block = Block::new()
            .title(
                ratatui::widgets::block::Title::from("|Discovery|".yellow())
                    .position(ratatui::widgets::block::Position::Top)
                    .alignment(Alignment::Right),
            )
            .title(
                ratatui::widgets::block::Title::from(Line::from(vec![
                    Span::styled("|", Style::default().fg(Color::Yellow)),
                    Span::styled(
                        "e",
                        Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                    ),
                    Span::styled("xport data", Style::default().fg(Color::Yellow)),
                    Span::styled("|", Style::default().fg(Color::Yellow)),
                ]))
                .alignment(Alignment::Left)
                .position(ratatui::widgets::block::Position::Bottom),
            )
            .title(
                ratatui::widgets::block::Title::from(Line::from(scan_title))
                    .position(ratatui::widgets::block::Position::Top)
                    .alignment(Alignment::Left),
            );

        let sort_col_label = match sort_column {
            crate::action::SortColumn::Hostname => "hostname",
            crate::action::SortColumn::Mac => "mac",
            crate::action::SortColumn::Vendor => "vendor",
            crate::action::SortColumn::Ip => "ip",
        };

        block = block.title(
            ratatui::widgets::block::Title::from(Line::from(vec![
                Span::styled(" ", Style::default()),
                Span::styled(
                    "o",
                    Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                ),
                Span::styled("rder ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    sort_col_label,
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                ),
                Span::styled(" ", Style::default()),
            ]))
            .position(ratatui::widgets::block::Position::Bottom)
            .alignment(Alignment::Right),
        );

        if is_scanning {
            block = block.title(
                ratatui::widgets::block::Title::from(Line::from(vec![
                    Span::styled("|", Style::default().fg(Color::Yellow)),
                    Span::styled(
                        "s",
                        Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                    ),
                    Span::styled("top", Style::default().fg(Color::Yellow)),
                    Span::styled(" k", Style::default().fg(Color::Yellow)),
                    Span::styled("|", Style::default().fg(Color::Yellow)),
                ]))
                .alignment(Alignment::Right)
                .position(ratatui::widgets::block::Position::Bottom),
            );
        }

        Table::new(
            rows,
            [
                Constraint::Length(16),
                Constraint::Length(19),
                Constraint::Fill(1),
                Constraint::Fill(1),
            ],
        )
        .header(header)
        .block(block)
        .highlight_symbol(String::from(char::from_u32(0x25b6).unwrap_or('>')).red())
        .column_spacing(1)
    }

    pub fn make_scrollbar<'a>() -> Scrollbar<'a> {
        Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .style(Style::default().fg(Color::Rgb(100, 100, 100)))
            .begin_symbol(None)
            .end_symbol(None)
    }

    fn make_input(&self, scroll: usize) -> Paragraph<'_> {
        Paragraph::new(self.input.value())
            .style(Style::default().fg(Color::Green))
            .scroll((0, scroll as u16))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(match self.mode {
                        Mode::Input => Style::default().fg(Color::Green),
                        Mode::Normal => Style::default().fg(Color::Rgb(100, 100, 100)),
                    })
                    .border_type(DEFAULT_BORDER_STYLE)
                    .title(
                        ratatui::widgets::block::Title::from(Line::from(vec![
                            Span::raw("|"),
                            Span::styled(
                                "s",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("can", Style::default().fg(Color::Yellow)),
                            Span::raw(" "),
                            Span::styled(
                                "k",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("ill", Style::default().fg(Color::Yellow)),
                            Span::raw(" "),
                            Span::styled(
                                "i",
                                Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                            ),
                            Span::styled("nput/ESC", Style::default().fg(Color::Yellow)),
                            Span::raw("|"),
                        ]))
                        .alignment(Alignment::Center)
                        .position(ratatui::widgets::block::Position::Bottom),
                    ),
            )
    }

    fn render_sort_menu(&self, f: &mut Frame<'_>, table_rect: Rect) {
        let popup_height: u16 = 8;
        let popup_width: u16 = 40;
        let center = table_rect.x.saturating_add(table_rect.width / 2);
        let x = center.saturating_sub(popup_width / 2);
        let y = table_rect.y + 1;

        let popup_rect = Rect::new(x, y, popup_width, popup_height);

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .title(" Sort by: ".blue().bold())
            .title_bottom(" Enter/↓ to select, Esc to close ".dark_gray());

        f.render_widget(block, popup_rect);

        let options = vec![
            ("IP", crate::action::SortColumn::Ip),
            ("MAC", crate::action::SortColumn::Mac),
            ("Hostname", crate::action::SortColumn::Hostname),
            ("Vendor", crate::action::SortColumn::Vendor),
        ];

        let items: Vec<ListItem> = options
            .iter()
            .enumerate()
            .map(|(idx, (label, _))| {
                if idx == self.sort_selected_idx {
                    ListItem::from(format!("▶ {}", label).cyan().bold().to_string())
                } else {
                    ListItem::from(format!("  {}", label).dark_gray().to_string())
                }
            })
            .collect();

        let list = List::new(items).block(Block::default().padding(Padding::new(0, 1, 0, 1)));
        f.render_widget(
            list,
            popup_rect.inner(Margin {
                vertical: 1,
                horizontal: 0,
            }),
        );
    }

    fn make_error(&mut self) -> Paragraph<'_> {
        Paragraph::new("CIDR parse error")
            .style(Style::default().fg(Color::Red))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Double)
                    .border_style(Style::default().fg(Color::Red)),
            )
    }

    fn make_spinner(&self) -> Span<'_> {
        let spinner = SPINNER_SYMBOLS[self.spinner_index];
        Span::styled(
            format!("{spinner}scanning.."),
            Style::default().fg(Color::Yellow),
        )
    }
}

impl Component for Discovery {
    fn init(&mut self, _area: Size) -> Result<()> {
        if self.cidr.is_none() {
            self.set_cidr(String::from(DEFAULT_IP), false);
        }
        match Oui::default() {
            Ok(s) => self.oui = Some(s),
            Err(_) => self.oui = None,
        }
        Ok(())
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    fn register_action_handler(&mut self, tx: UnboundedSender<Action>) -> Result<()> {
        self.action_tx = Some(tx);
        Ok(())
    }

    fn handle_key_events(&mut self, key: KeyEvent) -> Result<Option<Action>> {
        if self.active_tab != TabsEnum::Discovery {
            return Ok(None);
        }

        // Sort menu open — consume all keys so global j/k/etc. don't fire.
        if self.showing_sort_menu {
            match key.code {
                KeyCode::Up | KeyCode::Char('k') => {
                    if self.sort_selected_idx > 0 {
                        self.sort_selected_idx -= 1;
                    }
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    if self.sort_selected_idx < 3 {
                        self.sort_selected_idx += 1;
                    }
                }
                KeyCode::Enter => {
                    let col = match self.sort_selected_idx {
                        0 => crate::action::SortColumn::Ip,
                        1 => crate::action::SortColumn::Mac,
                        2 => crate::action::SortColumn::Hostname,
                        _ => crate::action::SortColumn::Vendor,
                    };
                    self.sort_column = col.clone();
                    self.showing_sort_menu = false;
                    return Ok(Some(Action::SortBy(col)));
                }
                KeyCode::Esc => {
                    self.showing_sort_menu = false;
                }
                _ => {}
            }
            return Ok(Some(Action::Refresh));
        }

        // `k` stops an active scan instead of navigating up.
        if self.is_scanning && self.mode == Mode::Normal && key.code == KeyCode::Char('k') {
            return Ok(Some(Action::StopScan));
        }

        // `o` toggles the sort menu (only when idle).
        if !self.is_scanning && self.mode == Mode::Normal && key.code == KeyCode::Char('o') {
            self.showing_sort_menu = !self.showing_sort_menu;
            if self.showing_sort_menu {
                self.sort_selected_idx = match self.sort_column {
                    crate::action::SortColumn::Ip => 0,
                    crate::action::SortColumn::Mac => 1,
                    crate::action::SortColumn::Hostname => 2,
                    crate::action::SortColumn::Vendor => 3,
                };
            }
            return Ok(Some(Action::Refresh));
        }

        match self.mode {
            Mode::Normal => Ok(None),
            Mode::Input => match key.code {
                KeyCode::Enter => {
                    if self.action_tx.is_some() {
                        self.set_cidr(self.input.value().to_string(), true);
                    }
                    Ok(Some(Action::ModeChange(Mode::Normal)))
                }
                KeyCode::Esc => Ok(None), // let global keymap handle Esc → NormalMode
                _ => {
                    self.input.handle_event(&Event::Key(key));
                    Ok(Some(Action::Refresh))
                }
            },
        }
    }

    fn update(&mut self, action: Action) -> Result<Option<Action>> {
        if self.is_scanning {
            if let Action::Tick = action {
                let mut s_index = self.spinner_index + 1;
                s_index %= SPINNER_SYMBOLS.len();
                self.spinner_index = s_index;
            }
        }

        if let Action::PingIpResponded(ref ip) = action {
            self.process_ip(ip);
        }

        if let Action::CountIp = action {
            self.ip_num += 1;
            let ip_count = match self.cidr {
                Some(cidr) => count_ipv4_net_length(cidr.network_length() as u32) as i32,
                None => 0,
            };
            if self.ip_num >= ip_count {
                self.is_scanning = false;
            }
        }

        // Coordinator finished — all workers exited normally or after stop.
        if let Action::ScanComplete = action {
            self.is_scanning = false;
        }

        if let Action::CidrError = action {
            self.cidr_error = true;
        }

        // Passive MAC update from ARP traffic captured by packetdump.
        if let Action::ArpRecieve(ref arp_data) = action {
            self.process_mac(arp_data.clone());
        }

        // Worker finished resolving hostname + MAC for a live host.
        if let Action::IpResolved {
            ref ip,
            ref hostname,
            ref mac,
        } = action
        {
            if let Some(entry) = self.scanned_ips.iter_mut().find(|e| e.ip == *ip) {
                if !hostname.is_empty() {
                    entry.hostname = hostname.clone();
                }
                if !mac.is_empty() && entry.mac.is_empty() {
                    entry.mac = mac.clone();
                    if let Some(oui) = &self.oui {
                        if let Ok(Some(oui_res)) = oui.lookup_by_mac(mac) {
                            entry.vendor = oui_res.company_name.clone();
                        }
                    }
                }
            }
            self.sort_scanned_ips();
        }

        if let Action::ScanCidr = action {
            if self.active_interface.is_some()
                && !self.is_scanning
                && self.active_tab == TabsEnum::Discovery
            {
                self.scan();
            }
        }

        if let Action::SortBy(ref column) = action {
            self.sort_column = column.clone();
            self.sort_scanned_ips();
        }

        if let Action::Help = action {
            self.showing_sort_menu = !self.showing_sort_menu;
        }

        if let Action::StopScan = action {
            self.is_scanning = false;
            self.scanner.stop();
            log::info!("Scan stopped by user");
        }

        if let Action::ActiveInterface(ref interface) = action {
            let intf = interface.clone();
            if self.active_interface.is_none() {
                self.set_active_subnet(&intf);
            }
            self.active_interface = Some(intf);
        }

        if self.active_tab == TabsEnum::Discovery {
            if let Action::Down = action {
                self.next_in_table();
            }
            if let Action::Up = action {
                self.previous_in_table();
            }

            if let Action::ModeChange(mode) = action {
                if self.is_scanning && mode == Mode::Input {
                    self.action_tx
                        .clone()
                        .unwrap()
                        .send(Action::ModeChange(Mode::Normal))
                        .unwrap();
                    return Ok(None);
                }
                if mode == Mode::Input {
                    self.cidr_error = false;
                }
                self.action_tx
                    .clone()
                    .unwrap()
                    .send(Action::AppModeChange(mode))
                    .unwrap();
                self.mode = mode;
            }
        }

        if let Action::TabChange(tab) = action {
            self.tab_changed(tab).unwrap();
        }

        Ok(None)
    }

    fn tab_changed(&mut self, tab: TabsEnum) -> Result<()> {
        self.active_tab = tab;
        Ok(())
    }

    fn draw(&mut self, f: &mut Frame<'_>, area: Rect) -> Result<()> {
        if self.active_tab != TabsEnum::Discovery {
            return Ok(());
        }

        let layout = get_vertical_layout(area);

        let mut table_rect = layout.bottom;
        table_rect.y += 1;
        table_rect.height -= 1;

        let table = Self::make_table(
            &self.scanned_ips,
            self.cidr,
            self.ip_num,
            self.is_scanning,
            &self.sort_column,
        );
        f.render_stateful_widget(table, table_rect, &mut self.table_state);

        let scrollbar = Self::make_scrollbar();
        let mut scroll_rect = table_rect;
        scroll_rect.y += 3;
        scroll_rect.height -= 3;
        f.render_stateful_widget(
            scrollbar,
            scroll_rect.inner(Margin {
                vertical: 1,
                horizontal: 1,
            }),
            &mut self.scrollbar_state,
        );

        if self.showing_sort_menu {
            self.render_sort_menu(f, table_rect);
        }

        if self.cidr_error {
            let ex = table_rect.width.saturating_sub(19 + 41);
            let error_rect = Rect::new(ex, table_rect.y + 1, 18, 3);
            let block = self.make_error();
            f.render_widget(block, error_rect);
        }

        let input_size: u16 = INPUT_SIZE as u16;
        let input_rect = Rect::new(
            table_rect.width.saturating_sub(input_size + 1),
            table_rect.y + 1,
            input_size,
            3,
        );

        let scroll = self.input.visual_scroll(INPUT_SIZE - 3);
        let mut block = self.make_input(scroll);
        if self.is_scanning {
            block = block.add_modifier(Modifier::DIM);
        }
        f.render_widget(block, input_rect);

        if let Mode::Input = self.mode {
            f.set_cursor_position(Position {
                x: input_rect.x
                    + ((self.input.visual_cursor()).max(scroll) - scroll) as u16
                    + 1,
                y: input_rect.y + 1,
            });
        }

        if self.is_scanning {
            let throbber = self.make_spinner();
            let throbber_rect = Rect::new(input_rect.x + 1, input_rect.y, 12, 1);
            f.render_widget(throbber, throbber_rect);
        }

        Ok(())
    }
}
