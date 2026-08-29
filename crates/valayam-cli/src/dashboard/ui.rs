use anyhow::Result;
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Paragraph, Row, Table},
    Terminal,
};
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::Duration;

use valayam_models::finding::FindingOwned;

struct App {
    findings: Vec<FindingOwned>,
    should_quit: bool,
}

impl App {
    fn new() -> App {
        App {
            findings: vec![],
            should_quit: false,
        }
    }
}

pub async fn run_dashboard(mut finding_rx: mpsc::Receiver<FindingOwned>, is_running: Arc<AtomicBool>) -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();

    loop {
        // Non-blocking channel read
        while let Ok(f) = finding_rx.try_recv() {
            app.findings.push(f);
        }

        terminal.draw(|f| run_ui(f, &app))?;

        if event::poll(Duration::from_millis(250))? {
            if let Event::Key(key) = event::read()? {
                if let KeyCode::Char('q') = key.code {
                    app.should_quit = true;
                }
            }
        }

        if app.should_quit || !is_running.load(Ordering::SeqCst) {
            break;
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

fn run_ui(f: &mut ratatui::Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints(
            [
                Constraint::Length(3),
                Constraint::Min(0),
            ]
            .as_ref(),
        )
        .split(f.area());

    let title = Paragraph::new(vec![
        Line::from(vec![
            Span::styled("Valayam Interactive Dashboard", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw(" (Press 'q' to exit)"),
        ]),
    ])
    .block(Block::default().borders(Borders::ALL));
    f.render_widget(title, chunks[0]);

    let mut rows = vec![];
    for finding in &app.findings {
        let severity_color = match finding.severity {
            valayam_models::finding::Severity::Critical => Color::Magenta,
            valayam_models::finding::Severity::High => Color::Red,
            valayam_models::finding::Severity::Medium => Color::Yellow,
            valayam_models::finding::Severity::Low => Color::Green,
            valayam_models::finding::Severity::Info => Color::Blue,
            _ => Color::White,
        };

        let severity_str = format!("{:?}", finding.severity);
        rows.push(Row::new(vec![
            Span::styled(severity_str, Style::default().fg(severity_color)),
            Span::raw(finding.template_name.clone()),
            Span::raw(finding.target.clone()),
        ]));
    }

    let widths = [
        Constraint::Percentage(15),
        Constraint::Percentage(40),
        Constraint::Percentage(45),
    ];
    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["Severity", "Template", "Target"])
                .style(Style::default().add_modifier(Modifier::BOLD)),
        )
        .block(Block::default().title("Findings").borders(Borders::ALL));

    f.render_widget(table, chunks[1]);
}
