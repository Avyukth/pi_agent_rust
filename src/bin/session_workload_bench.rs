//! Session workload benchmark helper:
//! - prepare: create a large session file with synthetic user messages
//! - workload: open/resume, append N messages, save, emit timing JSON

use std::path::{Path, PathBuf};
use std::time::Instant;

use pi::error::Result;
use pi::model::{AssistantMessage, ContentBlock, StopReason, TextContent, Usage, UserContent};
use pi::session::{Session, SessionMessage};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Mode {
    Prepare,
    Workload,
}

#[derive(Debug, Clone)]
struct Args {
    mode: Mode,
    session_path: PathBuf,
    messages: usize,
    append: usize,
}

#[derive(Debug, Serialize)]
struct Report {
    mode: String,
    session_path: String,
    existing_entries: usize,
    appended: usize,
    open_ms: f64,
    append_ms: f64,
    save_ms: f64,
    total_ms: f64,
    file_bytes: u64,
}

fn parse_args() -> Result<Args> {
    let mut mode = Mode::Workload;
    let mut session_path = PathBuf::from("/tmp/pi_session_bench/rust_large_session.jsonl");
    let mut messages = 5_000usize;
    let mut append = 10usize;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--mode" => {
                if let Some(value) = args.next() {
                    mode = match value.as_str() {
                        "prepare" => Mode::Prepare,
                        "workload" => Mode::Workload,
                        _ => {
                            return Err(pi::Error::session("invalid --mode; use prepare|workload"));
                        }
                    };
                } else {
                    return Err(pi::Error::session("--mode requires a value"));
                }
            }
            "--session" => {
                if let Some(value) = args.next() {
                    session_path = PathBuf::from(value);
                } else {
                    return Err(pi::Error::session("--session requires a value"));
                }
            }
            "--messages" => {
                if let Some(value) = args.next() {
                    messages = value
                        .parse::<usize>()
                        .map_err(|_| pi::Error::session("invalid --messages"))?;
                } else {
                    return Err(pi::Error::session("--messages requires a value"));
                }
            }
            "--append" => {
                if let Some(value) = args.next() {
                    append = value
                        .parse::<usize>()
                        .map_err(|_| pi::Error::session("invalid --append"))?;
                } else {
                    return Err(pi::Error::session("--append requires a value"));
                }
            }
            _ => {}
        }
    }

    Ok(Args {
        mode,
        session_path,
        messages,
        append,
    })
}

fn ensure_parent_dir(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| pi::Error::session("session path has no parent"))?;
    std::fs::create_dir_all(parent)?;
    Ok(())
}

fn append_user_messages(session: &mut Session, count: usize, prefix: &str) {
    for idx in 0..count {
        session.append_message(SessionMessage::User {
            content: UserContent::Text(format!("{prefix} {idx}")),
            timestamp: None,
        });
    }
}

fn append_seed_messages_mixed(session: &mut Session, count: usize) {
    for idx in 0..count {
        if idx % 2 == 0 {
            session.append_message(SessionMessage::User {
                content: UserContent::Text(format!("seed user {idx}")),
                timestamp: None,
            });
            continue;
        }

        let assistant = AssistantMessage {
            content: vec![ContentBlock::Text(TextContent::new(format!(
                "seed assistant {idx}"
            )))],
            api: "benchmark".to_string(),
            provider: "benchmark".to_string(),
            model: "benchmark".to_string(),
            usage: Usage::default(),
            stop_reason: StopReason::Stop,
            error_message: None,
            timestamp: 0,
        };
        session.append_message(SessionMessage::Assistant { message: assistant });
    }
}

fn report_to_json(report: &Report) -> Result<String> {
    serde_json::to_string(report).map_err(|err| pi::Error::Json(Box::new(err)))
}

const fn mode_to_str(mode: &Mode) -> &'static str {
    match mode {
        Mode::Prepare => "prepare",
        Mode::Workload => "workload",
    }
}

fn run() -> Result<()> {
    let args = parse_args()?;
    ensure_parent_dir(&args.session_path)?;

    if args.mode == Mode::Prepare {
        let mut session = Session::create();
        session.path = Some(args.session_path.clone());

        let append_started = Instant::now();
        append_seed_messages_mixed(&mut session, args.messages);
        let append_ms = append_started.elapsed().as_secs_f64() * 1000.0;

        let save_started = Instant::now();
        let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
            .build()
            .map_err(|err| pi::Error::session(format!("runtime init failed: {err}")))?;
        runtime.block_on(async { session.save().await })?;
        let save_ms = save_started.elapsed().as_secs_f64() * 1000.0;

        let file_bytes = std::fs::metadata(&args.session_path)?.len();
        let report = Report {
            mode: mode_to_str(&args.mode).to_string(),
            session_path: args.session_path.display().to_string(),
            existing_entries: args.messages,
            appended: args.messages,
            open_ms: 0.0,
            append_ms,
            save_ms,
            total_ms: append_ms + save_ms,
            file_bytes,
        };

        println!("{}", report_to_json(&report)?);
        return Ok(());
    }

    let runtime = asupersync::runtime::RuntimeBuilder::current_thread()
        .build()
        .map_err(|err| pi::Error::session(format!("runtime init failed: {err}")))?;

    let open_started = Instant::now();
    let mut session = runtime
        .block_on(async { Session::open(args.session_path.to_string_lossy().as_ref()).await })?;
    let open_ms = open_started.elapsed().as_secs_f64() * 1000.0;
    let existing_entries = session.entries.len();

    let append_started = Instant::now();
    append_user_messages(&mut session, args.append, "workload append");
    let append_ms = append_started.elapsed().as_secs_f64() * 1000.0;

    let save_started = Instant::now();
    runtime.block_on(async { session.save().await })?;
    let save_ms = save_started.elapsed().as_secs_f64() * 1000.0;

    let total_ms = open_ms + append_ms + save_ms;
    let file_bytes = std::fs::metadata(&args.session_path)?.len();
    let report = Report {
        mode: mode_to_str(&args.mode).to_string(),
        session_path: args.session_path.display().to_string(),
        existing_entries,
        appended: args.append,
        open_ms,
        append_ms,
        save_ms,
        total_ms,
        file_bytes,
    };

    println!("{}", report_to_json(&report)?);
    Ok(())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("session_workload_bench error: {err}");
        std::process::exit(1);
    }
}
