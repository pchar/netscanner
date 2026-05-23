use cidr::Ipv4Cidr;
use color_eyre::eyre::Result;
use color_eyre::owo_colors::OwoColorize;
use dns_lookup::lookup_addr;
use futures::future::join_all;
use futures::stream;
use futures::StreamExt;

use pnet::datalink::{Channel, NetworkInterface};
use pnet::packet::{
    arp::{ArpHardwareTypes, ArpOperations, MutableArpPacket},
    ethernet::{EtherTypes, MutableEthernetPacket},
    MutablePacket, Packet,
};
use pnet::util::MacAddr;

use core::str;
use ratatui::layout::Position;
use ratatui::{prelude::*, widgets::*};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use surge_ping::{Client, Config, IcmpPacket, PingIdentifier, PingSequence, ICMP};
use tokio::{
    sync::mpsc::UnboundedSender,
    task::JoinHandle,
};

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
use rand::random;
use tui_input::backend::crossterm::EventHandler;
use tui_input::Input;

static POOL_SIZE: usize = 32;
static INPUT_SIZE: usize = 30;
static DEFAULT_IP: &str = "192.168.1.0/24";
const SPINNER_SYMBOLS: [&str; 6] = ["⠷", "⠯", "⠟", "⠻", "⠽", "⠾"];

// Standalone ARP sender — safe to call from spawn_blocking.
fn send_arp_to(interface: &NetworkInterface, target_ip: Ipv4Addr) {
    let mac = match interface.mac {
        Some(m) => m,
        None => return,
    };
    let ipv4 = match interface.ips.iter().find(|ip| ip.is_ipv4()) {
        Some(ip) => match ip.ip() {
            IpAddr::V4(v4) => v4,
            _ => return,
        },
        None => return,
    };
    let (mut sender, _) = match pnet::datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        _ => return,
    };
    let mut eth_buf = [0u8; 42];
    let mut eth_pkt = MutableEthernetPacket::new(&mut eth_buf).unwrap();
    eth_pkt.set_destination(MacAddr::broadcast());
    eth_pkt.set_source(mac);
    eth_pkt.set_ethertype(EtherTypes::Arp);

    let mut arp_buf = [0u8; 28];
    let mut arp_pkt = MutableArpPacket::new(&mut arp_buf).unwrap();
    arp_pkt.set_hardware_type(ArpHardwareTypes::Ethernet);
    arp_pkt.set_protocol_type(EtherTypes::Ipv4);
    arp_pkt.set_hw_addr_len(6);
    arp_pkt.set_proto_addr_len(4);
    arp_pkt.set_operation(ArpOperations::Request);
    arp_pkt.set_sender_hw_addr(mac);
    arp_pkt.set_sender_proto_addr(ipv4);
    arp_pkt.set_target_hw_addr(MacAddr::zero());
    arp_pkt.set_target_proto_addr(target_ip);
    eth_pkt.set_payload(arp_pkt.packet_mut());
    let _ = sender.send_to(eth_pkt.packet(), None);
}

// Reads the OS ARP cache without sleeping — caller should sleep first.
fn lookup_mac_from_arp(ip: &str) -> Option<String> {
    let output = std::process::Command::new("arp")
        .arg("-a")
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())?;
    for line in output.lines() {
        if !line.contains(ip) {
            continue;
        }
        let mac = line.split_whitespace().find(|p| {
            p.len() >= 11
                && (p.contains(':') || p.contains('-'))
                && p.chars().all(|c| c.is_ascii_hexdigit() || c == ':' || c == '-')
        });
        if let Some(m) = mac {
            return Some(m.replace('-', ":"));
        }
    }
    None
}

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
    task: JoinHandle<()>,
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
            task: tokio::spawn(async {}),
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
                self.scanned_ips.sort_by(|a, b| {
                    a.hostname
                        .to_lowercase()
                        .cmp(&b.hostname.to_lowercase())
                });
            }
            crate::action::SortColumn::Mac => {
                self.scanned_ips.sort_by(|a, b| a.mac.to_lowercase().cmp(&b.mac.to_lowercase()));
            }
            crate::action::SortColumn::Vendor => {
                self.scanned_ips.sort_by(|a, b| {
                    a.vendor.to_lowercase().cmp(&b.vendor.to_lowercase())
                });
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
            Err(e) => {
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


    // fn scan(&mut self) {
    //     self.reset_scan();

    //     if let Some(cidr) = self.cidr {
    //         self.is_scanning = true;
    //         let tx = self.action_tx.as_ref().unwrap().clone();
    //         self.task = tokio::spawn(async move {
    //             let ips = get_ips4_from_cidr(cidr);
    //             let chunks: Vec<_> = ips.chunks(POOL_SIZE).collect();
    //             for chunk in chunks {
    //                 let tasks: Vec<_> = chunk
    //                     .iter()
    //                     .map(|&ip| {
    //                         let tx = tx.clone();
    //                         let closure = || async move {
    //                             let client =
    //                                 Client::new(&Config::default()).expect("Cannot create client");
    //                             let payload = [0; 56];
    //                             let mut pinger = client
    //                                 .pinger(IpAddr::V4(ip), PingIdentifier(random()))
    //                                 .await;
    //                             pinger.timeout(Duration::from_secs(2));

    //                             match pinger.ping(PingSequence(2), &payload).await {
    //                                 Ok((IcmpPacket::V4(packet), dur)) => {
    //                                     tx.send(Action::PingIp(packet.get_real_dest().to_string()))
    //                                         .unwrap_or_default();
    //                                     tx.send(Action::CountIp).unwrap_or_default();
    //                                 }
    //                                 Ok(_) => {
    //                                     tx.send(Action::CountIp).unwrap_or_default();
    //                                 }
    //                                 Err(_) => {
    //                                     tx.send(Action::CountIp).unwrap_or_default();
    //                                 }
    //                             }
    //                         };
    //                         task::spawn(closure())
    //                     })
    //                     .collect();

    //                 let _ = join_all(tasks).await;
    //             }
    //         });
    //     };
    // }

    fn scan(&mut self) {
        self.reset_scan();

        if let Some(cidr) = self.cidr {
            self.is_scanning = true;

            let tx = self.action_tx.clone().unwrap();
            let cidr_clone = self.cidr;

            // Run the scan in a separate OS thread with its own Tokio runtime.
            // This avoids two problems:
            // 1. surge_ping's raw ICMP sockets (sendto/recvfrom) are blocking syscalls
            //    that would freeze the main event loop if run on a worker thread.
            // 2. Creating a runtime inside tokio::spawn_blocking still nests inside
            //    the outer runtime (same error as below), so we use std::thread::spawn
            //    for a truly independent thread.
            self.task = tokio::spawn(async move {
                if let Some(cidr) = cidr_clone {
                    let ips = get_ips4_from_cidr(cidr);
                    let ips_vec: Vec<Ipv4Addr> = ips.to_vec();

                    // Exactly 3 worker threads for network background tasks.
                    // Each thread does blocking ICMP syscalls (sendto/recvfrom)
                    // so they never block the main event loop.
                    let tx_thread = tx.clone();
                    let num_threads = 3;

                    // Split IPs across 3 threads
                    let chunk_size = (ips_vec.len() + num_threads - 1) / num_threads;
                    let chunks: Vec<_> = ips_vec
                        .chunks(chunk_size)
                        .map(|c| c.to_vec())
                        .collect();

                    for ips in chunks {
                        let tx = tx_thread.clone();
                        // Run blocking ICMP syscalls directly on this OS thread
                        // (no tokio runtime needed since pings are blocking)
                        std::thread::spawn(move || {
                            for ip in ips {
                                let tx = tx.clone();
                                // surge_ping's async API needs a tokio runtime, so we spawn
                                // a mini runtime on this thread to run the blocking pinger
                                let rt = tokio::runtime::Builder::new_current_thread()
                                    .enable_all()
                                    .build()
                                    .expect("Failed to build worker runtime");
                                rt.block_on(async {
                                    let client =
                                        Client::new(&Config::default()).expect("Cannot create client");
                                    let payload = [0; 56];
                                    let mut pinger = client
                                        .pinger(IpAddr::V4(ip), PingIdentifier(random()))
                                        .await;
                                    pinger.timeout(Duration::from_secs(2));

                                    match pinger.ping(PingSequence(2), &payload).await {
                                        Ok((IcmpPacket::V4(packet), _)) => {
                                            // Only send PingIpResponded for IPs that actually reply
                                            tx.send(Action::PingIpResponded(packet.get_real_dest().to_string()))
                                                .unwrap_or_default();
                                            tx.send(Action::CountIp).unwrap_or_default();
                                        }
                                        Ok((IcmpPacket::V6(_), _)) => {
                                            // IPv6 pings - just count as complete
                                            tx.send(Action::CountIp).unwrap_or_default();
                                        }
                                        Err(_) => {
                                            // Failed ping - don't send PingIpResponded
                                            tx.send(Action::CountIp).unwrap_or_default();
                                        }
                                    }
                                });
                            }
                        });
                    }
                }
            });
        };
    }

    fn process_mac(&mut self, arp_data: ArpPacketData) {
        if let Some(n) = self
            .scanned_ips
            .iter_mut()
            .find(|item| item.ip == arp_data.sender_ip.to_string())
        {
            n.mac = arp_data.sender_mac.to_string();

            if let Some(oui) = &self.oui {
                let oui_res = oui.lookup_by_mac(&n.mac);
                if let Ok(Some(oui_res)) = oui_res {
                    let cn = oui_res.company_name.clone();
                    n.vendor = cn;
                }
            }
        }
    }

    fn process_ip(&mut self, ip: &str) {
        // Add placeholder entry immediately so the table updates in real time.
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

        // All blocking work (DNS + ARP probe + cache read) runs off the event loop.
        let tx = self.action_tx.as_ref().unwrap().clone();
        let ip_str = ip.to_string();
        let interface = self.active_interface.clone();

        tokio::spawn(async move {
            // 1. Reverse-DNS lookup
            let hip: IpAddr = ip_str.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
            let hostname = tokio::task::spawn_blocking(move || {
                lookup_addr(&hip).unwrap_or_default()
            })
            .await
            .unwrap_or_default();

            // 2. Send ARP probe so the OS ARP cache gets populated
            if let Some(intf) = interface {
                if let Ok(ipv4) = ip_str.parse::<Ipv4Addr>() {
                    tokio::task::spawn_blocking(move || send_arp_to(&intf, ipv4))
                        .await
                        .ok();
                }
            }

            // 3. Give the kernel ~300 ms to update its ARP cache
            tokio::time::sleep(Duration::from_millis(300)).await;

            // 4. Read MAC from ARP cache (non-sleeping, fast)
            let ip_for_mac = ip_str.clone();
            let mac = tokio::task::spawn_blocking(move || {
                lookup_mac_from_arp(&ip_for_mac)
            })
            .await
            .unwrap_or(None)
            .unwrap_or_default();

            tx.send(Action::IpResolved { ip: ip_str, hostname, mac }).ok();
        });
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
        let mut ip_len = 0;
        if !self.scanned_ips.is_empty() {
            ip_len = self.scanned_ips.len() - 1;
        }
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
                let mut s_ip_len = 0;
                if !self.scanned_ips.is_empty() {
                    s_ip_len = self.scanned_ips.len() - 1;
                }
                if index >= s_ip_len {
                    0
                } else {
                    index + 1
                }
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

        // Show sort column name
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
                Span::styled(sort_col_label, Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
                Span::styled(" ", Style::default()),
            ]))
            .position(ratatui::widgets::block::Position::Bottom)
            .alignment(Alignment::Right),
        );

        // Show "stop k" command when scanning
        if is_scanning {
            block = block.title(
                ratatui::widgets::block::Title::from(Line::from(vec![
                    Span::styled("|", Style::default().fg(Color::Yellow)),
                    Span::styled(
                        "s",
                        Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
                    ),
                    Span::styled("top", Style::default().fg(Color::Yellow)),
                    Span::styled(
                        " k",
                        Style::default().fg(Color::Yellow),
                    ),
                    Span::styled("|", Style::default().fg(Color::Yellow)),
                ]))
                .alignment(Alignment::Right)
                .position(ratatui::widgets::block::Position::Bottom),
            );
        }

        let table = Table::new(rows, [
            Constraint::Length(16),
            Constraint::Length(19),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ])
        .header(header)
        .block(block)
        .highlight_symbol(String::from(char::from_u32(0x25b6).unwrap_or('>')).red())
        .column_spacing(1);
        table
    }

    pub fn make_scrollbar<'a>() -> Scrollbar<'a> {
        let scrollbar = Scrollbar::default()
            .orientation(ScrollbarOrientation::VerticalRight)
            .style(Style::default().fg(Color::Rgb(100, 100, 100)))
            .begin_symbol(None)
            .end_symbol(None);
        scrollbar
    }

    fn make_input(&self, scroll: usize) -> Paragraph<'_> {
        let input = Paragraph::new(self.input.value())
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
            );
        input
    }

    fn render_sort_menu(&self, f: &mut Frame<'_>, table_rect: Rect) {
        let popup_height: u16 = 8;
        let popup_width: u16 = 40;
        let center = table_rect.x.saturating_add(table_rect.width / 2);
        let x = center.saturating_sub(popup_width / 2);
        let y = table_rect.y + 1;

        let popup_rect = Rect::new(x, y, popup_width, popup_height);

        // Create the popup block with focus indicator
        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
            .title(" Sort by: ".blue().bold())
            .title_bottom(" Enter/↓ to select, Esc to close ".dark_gray());

        f.render_widget(block, popup_rect);

        // Create list of sort options
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
                let selected = idx == self.sort_selected_idx;
                if selected {
                    ListItem::from(format!("▶ {}", label).cyan().bold().to_string())
                } else {
                    ListItem::from(format!("  {}", label).dark_gray().to_string())
                }
            })
            .collect();

        let list = List::new(items).block(Block::default().padding(Padding::new(0, 1, 0, 1)));
        f.render_widget(list, popup_rect.inner(Margin { vertical: 1, horizontal: 0 }));
    }

    fn make_error(&mut self) -> Paragraph<'_> {
        let error = Paragraph::new("CIDR parse error")
            .style(Style::default().fg(Color::Red))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(BorderType::Double)
                    .border_style(Style::default().fg(Color::Red)),
            );
        error
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
    fn init(&mut self, area: Size) -> Result<()> {
        if self.cidr.is_none() {
            self.set_cidr(String::from(DEFAULT_IP), false);
        }
        // -- init oui
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

        // Sort menu is open — consume ALL keys so global j/k/etc. don't fire.
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
                    // Return the action so update() applies the sort.
                    return Ok(Some(Action::SortBy(col)));
                }
                KeyCode::Esc => {
                    self.showing_sort_menu = false;
                }
                _ => {}
            }
            // Key consumed by the sort menu — block global keymap.
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

        // -- custom actions
        if let Action::PingIpResponded(ref ip) = action {
            self.process_ip(ip);
        }
        // -- count IPs
        if let Action::CountIp = action {
            self.ip_num += 1;

            let ip_count = match self.cidr {
                Some(cidr) => count_ipv4_net_length(cidr.network_length() as u32) as i32,
                None => 0,
            };

            if self.ip_num == ip_count {
                self.is_scanning = false;
            }
        }
        // -- CIDR error
        if let Action::CidrError = action {
            self.cidr_error = true;
        }
        // -- ARP packet received (parallel MAC update from captured traffic)
        if let Action::ArpRecieve(ref arp_data) = action {
            self.process_mac(arp_data.clone());
        }
        // -- background IP resolution completed
        if let Action::IpResolved { ref ip, ref hostname, ref mac } = action {
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
        // -- Scan CIDR
        if let Action::ScanCidr = action {
            if self.active_interface.is_some()
                && !self.is_scanning
                && self.active_tab == TabsEnum::Discovery
            {
                self.scan();
            }
        }

        // -- Sort by column
        if let Action::SortBy(ref column) = action {
            self.sort_column = column.clone();
            self.sort_scanned_ips();
        }

        // -- Toggle sort menu
        if let Action::Help = action {
            self.showing_sort_menu = !self.showing_sort_menu;
        }

        // -- Stop Scan
        if let Action::StopScan = action {
            self.is_scanning = false;
            log::info!("Scan stopped by user");
        }
        // -- active interface
        if let Action::ActiveInterface(ref interface) = action {
            let intf = interface.clone();
            // -- first time scan after setting of interface
            if self.active_interface.is_none() {
                self.set_active_subnet(&intf);
            }
            self.active_interface = Some(intf);
        }

        if self.active_tab == TabsEnum::Discovery {
            // -- prev & next select item in table
            if let Action::Down = action {
                self.next_in_table();
            }
            if let Action::Up = action {
                self.previous_in_table();
            }

            // -- MODE CHANGE
            if let Action::ModeChange(mode) = action {
                // -- when scanning don't switch to input mode
                if self.is_scanning && mode == Mode::Input {
                    self.action_tx
                        .clone()
                        .unwrap()
                        .send(Action::ModeChange(Mode::Normal))
                        .unwrap();
                    return Ok(None);
                }

                if mode == Mode::Input {
                    // self.input.reset();
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

        // -- tab change
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
        if self.active_tab == TabsEnum::Discovery {
            let layout = get_vertical_layout(area);

            // -- TABLE
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

            // -- SCROLLBAR
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

            // -- SORT MENU POPUP
            if self.showing_sort_menu {
                self.render_sort_menu(f, table_rect);
            }

            // -- ERROR
            if self.cidr_error {
                let ex = table_rect.width.saturating_sub(19 + 41);
                let error_rect = Rect::new(ex, table_rect.y + 1, 18, 3);
                let block = self.make_error();
                f.render_widget(block, error_rect);
            }

            // -- INPUT
            let input_size: u16 = INPUT_SIZE as u16;
            let input_rect = Rect::new(
                table_rect.width.saturating_sub(input_size + 1),
                table_rect.y + 1,
                input_size,
                3,
            );

            // -- INPUT_SIZE - 3 is offset for border + 1char for cursor
            let scroll = self.input.visual_scroll(INPUT_SIZE - 3);
            let mut block = self.make_input(scroll);
            if self.is_scanning {
                block = block.add_modifier(Modifier::DIM);
            }
            f.render_widget(block, input_rect);

            // -- cursor
            match self.mode {
                Mode::Input => {
                    f.set_cursor_position(Position {
                        x: input_rect.x
                            + ((self.input.visual_cursor()).max(scroll) - scroll) as u16
                            + 1,
                        y: input_rect.y + 1,
                    });
                }
                Mode::Normal => {}
            }

            // -- THROBBER
            if self.is_scanning {
                let throbber = self.make_spinner();
                let throbber_rect = Rect::new(input_rect.x + 1, input_rect.y, 12, 1);
                f.render_widget(throbber, throbber_rect);
            }
        }

        Ok(())
    }
}
