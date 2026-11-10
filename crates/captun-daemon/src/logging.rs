//! Logging to stderr and to a log file (the service usually runs without a
//! console), plus a layer that passes warnings and errors from our own crates
//! on to connected GUIs.

use std::{
    fmt::Write as _,
    fs::{self, File, OpenOptions},
    io::{self, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
    sync::Mutex,
    time::{Duration, Instant},
};

use captun_core::time::now_millis;
use captun_ipc::{Event, LogLevel, LogLine};
use tokio::sync::broadcast;
use tracing::{
    Level, Subscriber,
    field::{Field, Visit},
    level_filters::LevelFilter,
};
use tracing_subscriber::{EnvFilter, Layer, layer::Context, prelude::*};

/// Where a log file is full: it becomes `.log.1`, the one before that
/// `.log.2`, and an older one goes. So the logs never take much more than
/// three times this, however much is logged.
const MAX_LOG_BYTES: u64 = 16 * 1024 * 1024;
/// When a full log cannot be moved aside (another program holds it open
/// without allowing that), how much more goes into it before the next try.
/// Once it holds twice its size it is cut in place instead.
const RETRY_AFTER_BYTES: u64 = 1024 * 1024;
/// The line a log cut in place starts with.
const CUT_NOTE: &str =
    "Older lines were cut here: the full log could not be moved aside, most likely because another program has it open.\n";
/// How often a log file that could not be made is tried again.
const REOPEN_EVERY: Duration = Duration::from_secs(60);
/// The most lines a second passed on to GUIs.
const GUI_LINES_PER_SECOND: u32 = 10;

pub(crate) fn init(filter: &str, events: broadcast::Sender<Event>, log_file: &Path) -> anyhow::Result<()> {
    let file_filter = EnvFilter::try_new(filter)?;
    let file = tracing_subscriber::fmt::layer()
        .with_ansi(false)
        .with_writer(Mutex::new(LogFile::open(log_file, MAX_LOG_BYTES)))
        .with_filter(file_filter);
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr).with_filter(EnvFilter::try_new(filter)?))
        .with(file)
        // A filter of its own, so lower levels are not even built for it.
        .with(GuiLayer::new(events).with_filter(LevelFilter::WARN))
        .try_init()?;
    // The service runs without a console, so a panic would otherwise leave no
    // trace: write it to the log first.
    let report = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // netdev's known failure while reading the adapters is caught and
        // reported where it happens.
        if captun_platform::iface::listing() {
            return;
        }
        tracing::error!("the service panicked: {info}");
        report(info);
    }));
    Ok(())
}

/// `path` with `suffix` after its extension: `captun-daemon.log.1`.
fn older(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

/// A new file at `path`, never one already there. On Windows a link planted
/// at that name is not followed either (`FILE_FLAG_OPEN_REPARSE_POINT`),
/// which would point the elevated service's writes at a file of someone
/// else's choosing; elsewhere `O_EXCL` already refuses to follow one.
fn create_new(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        /// Opens a link itself, not what it points to (WinBase.h).
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    match options.open(path) {
        // The log was just moved aside, so whatever is there was left
        // behind or planted. Removing a link removes the link alone.
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
            fs::remove_file(path)?;
            options.open(path)
        }
        other => other,
    }
}

/// The service's log file. It starts afresh once it holds `max_bytes`, and
/// keeps the two before it, so it cannot fill the disk whatever devices make
/// the service log.
#[derive(Debug)]
struct LogFile {
    path: PathBuf,
    max_bytes: u64,
    /// `None` while it cannot be made; lines are then lost (stderr has them).
    file: Option<File>,
    written: u64,
    /// When the file holds this much, it is moved aside.
    rotate_at: u64,
    /// When making the file last failed.
    failed_at: Option<Instant>,
}

impl LogFile {
    /// This run's log, with the previous runs' kept beside it as `.1` and `.2`.
    fn open(path: &Path, max_bytes: u64) -> Self {
        if let Some(dir) = path.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let mut log =
            Self { path: path.to_owned(), max_bytes, file: None, written: 0, rotate_at: max_bytes, failed_at: None };
        let _ = fs::rename(older(path, ".1"), older(path, ".2"));
        let _ = fs::rename(path, older(path, ".1"));
        log.create();
        log
    }

    fn create(&mut self) {
        match create_new(&self.path) {
            Ok(file) => {
                self.file = Some(file);
                self.written = 0;
                self.rotate_at = self.max_bytes;
                self.failed_at = None;
            }
            Err(e) => {
                // Not through tracing: this is where its lines go.
                if self.failed_at.is_none() {
                    eprintln!("cannot write the log file {}: {e}", self.path.display());
                }
                self.file = None;
                self.failed_at = Some(Instant::now());
            }
        }
    }

    /// Moves the full log to `.1` (and `.1` to `.2`) and starts a new one.
    fn rotate(&mut self) {
        let first = older(&self.path, ".1");
        let _ = fs::rename(&first, older(&self.path, ".2"));
        // Moved while still open: std opens files letting others rename them.
        if fs::rename(&self.path, &first).is_err() {
            // Held open by a program that does not allow that (someone
            // watching the log, say): carry on in it and try again shortly,
            // but never let it grow past twice its size.
            if self.written >= self.max_bytes.saturating_mul(2) && self.cut() {
                return;
            }
            self.rotate_at = self.written.saturating_add(RETRY_AFTER_BYTES.min(self.max_bytes));
            return;
        }
        self.file = None;
        self.create();
    }

    /// Empties the log in place and says so in its first line. This handle
    /// may write, so any other program with the file open allows writing,
    /// which is what cutting it needs. Says whether it worked.
    fn cut(&mut self) -> bool {
        let Some(file) = self.file.as_mut() else { return false };
        if file.set_len(0).and_then(|()| file.seek(SeekFrom::Start(0))).and_then(|_| file.write_all(CUT_NOTE.as_bytes())).is_err() {
            return false;
        }
        self.written = CUT_NOTE.len() as u64;
        self.rotate_at = self.max_bytes;
        true
    }
}

impl Write for LogFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.file.is_some() && self.written >= self.rotate_at {
            self.rotate();
        } else if self.file.is_none() && self.failed_at.is_none_or(|at| at.elapsed() >= REOPEN_EVERY) {
            self.create();
        }
        let Some(file) = self.file.as_mut() else {
            // The log is a help, not a duty: the line is lost, not the event.
            return Ok(buf.len());
        };
        let n = file.write(buf)?;
        self.written = self.written.saturating_add(n as u64);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.as_mut().map_or(Ok(()), File::flush)
    }
}

/// Passes warnings and errors on to connected GUIs, at most
/// [`GUI_LINES_PER_SECOND`] a second; what it leaves out it counts and says.
struct GuiLayer {
    events: broadcast::Sender<Event>,
    budget: Mutex<Budget>,
}

impl GuiLayer {
    fn new(events: broadcast::Sender<Event>) -> Self {
        Self { events, budget: Mutex::new(Budget::new(Instant::now())) }
    }
}

/// Lines passed on in the current second, and those left out since the last
/// one that went.
#[derive(Debug)]
struct Budget {
    second: Instant,
    sent: u32,
    left_out: u32,
}

impl Budget {
    fn new(now: Instant) -> Self {
        Self { second: now, sent: 0, left_out: 0 }
    }

    /// Whether a line may go at `now`: `Some` with how many were left out
    /// before it, to say first, or `None` when it is left out itself.
    fn take(&mut self, now: Instant) -> Option<u32> {
        if now.saturating_duration_since(self.second) >= Duration::from_secs(1) {
            self.second = now;
            self.sent = 0;
        }
        if self.sent >= GUI_LINES_PER_SECOND {
            self.left_out = self.left_out.saturating_add(1);
            return None;
        }
        self.sent += 1;
        Some(std::mem::take(&mut self.left_out))
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }
}

impl<S: Subscriber> Layer<S> for GuiLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        if !meta.target().starts_with("captun") {
            return;
        }
        let level = match *meta.level() {
            Level::ERROR => LogLevel::Error,
            Level::WARN => LogLevel::Warn,
            _ => return,
        };
        if self.events.receiver_count() == 0 {
            return;
        }
        let taken = self.budget.lock().unwrap_or_else(|poisoned| poisoned.into_inner()).take(Instant::now());
        let Some(left_out) = taken else { return };
        let at_ms = now_millis();
        if left_out > 0 {
            let _ = self.events.send(Event::Log(LogLine {
                at_ms,
                level: LogLevel::Warn,
                target: module_path!().to_owned(),
                message: format!(
                    "{left_out} more warnings and errors were not shown here because too many came at once; the service's log file has them"
                ),
            }));
        }
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let _ = self.events.send(Event::Log(LogLine {
            at_ms,
            level,
            target: meta.target().to_owned(),
            message: visitor.message + &visitor.fields,
        }));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("captun-log-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// One line in one write, as the log's formatter writes them.
    fn line(log: &mut LogFile, n: usize) {
        log.write_all(format!("line {n:04} ................................\n").as_bytes()).unwrap();
    }

    #[test]
    fn a_full_log_starts_afresh_and_three_are_kept() {
        let dir = scratch("rotate");
        let path = dir.join("captun-daemon.log");
        fs::write(&path, "the previous run\n").unwrap();
        let mut log = LogFile::open(&path, 1024);
        assert_eq!(fs::read_to_string(older(&path, ".1")).unwrap(), "the previous run\n");

        for n in 0..200 {
            line(&mut log, n);
        }
        log.flush().unwrap();
        for file in [path.clone(), older(&path, ".1"), older(&path, ".2")] {
            let len = fs::metadata(&file).unwrap().len();
            assert!(len <= 1024 + 64, "{} holds {len} bytes", file.display());
        }
        assert!(!older(&path, ".3").exists(), "only three are kept");
        let newest = fs::read_to_string(&path).unwrap();
        assert!(newest.ends_with("line 0199 ................................\n"), "{newest}");
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 3);
        drop(log);
        let _ = fs::remove_dir_all(dir);
    }

    /// A log that cannot be moved aside (here a folder sits at `.1`, as a
    /// program holding the log open stops it on Windows) is tried again a
    /// little later, and cut in place once it holds twice its size, so a
    /// flood of lines still cannot fill the disk.
    #[test]
    fn a_log_that_cannot_be_moved_aside_is_cut_in_place() {
        let dir = scratch("cut");
        let path = dir.join("captun-daemon.log");
        for name in [".1", ".2"] {
            let folder = older(&path, name);
            fs::create_dir_all(&folder).unwrap();
            fs::write(folder.join("keep"), "in the way").unwrap();
        }
        let mut log = LogFile::open(&path, 1024);
        // Lines of 43 bytes: not moved aside at 1 KiB (line 24), nor 1 KiB
        // later, by which time it holds 2 KiB (line 48), so it is cut.
        for n in 0..60 {
            line(&mut log, n);
            assert!(fs::metadata(&path).unwrap().len() <= 2 * 1024 + 64, "never much past twice its size");
        }
        log.flush().unwrap();
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with(CUT_NOTE), "{text}");
        assert!(text.contains("line 0048") && !text.contains("line 0047"), "the older lines went: {text}");
        assert!(text.ends_with("line 0059 ................................\n"), "{text}");
        assert!(older(&path, ".1").join("keep").exists(), "whatever was in the way is left alone");

        // However much is written.
        for n in 0..400 {
            line(&mut log, n);
            assert!(fs::metadata(&path).unwrap().len() <= 2 * 1024 + 64);
        }
        log.flush().unwrap();
        assert!(fs::read_to_string(&path).unwrap().starts_with(CUT_NOTE));
        drop(log);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn something_left_at_the_logs_name_is_replaced_not_written_into() {
        let dir = scratch("leftover");
        let path = dir.join("captun-daemon.log");
        fs::write(&path, "old").unwrap();
        let mut file = create_new(&path).unwrap();
        file.write_all(b"new").unwrap();
        drop(file);
        assert_eq!(fs::read_to_string(&path).unwrap(), "new");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_link_planted_at_the_logs_name_is_not_followed() {
        let dir = scratch("link");
        let path = dir.join("captun-daemon.log");
        let target = dir.join("somewhere-else.txt");
        #[cfg(unix)]
        let planted = std::os::unix::fs::symlink(&target, &path);
        #[cfg(windows)]
        let planted = std::os::windows::fs::symlink_file(&target, &path);
        // Windows lets only administrators (or developer mode) make links.
        if planted.is_err() {
            let _ = fs::remove_dir_all(dir);
            return;
        }
        let mut file = create_new(&path).unwrap();
        file.write_all(b"log").unwrap();
        drop(file);
        assert!(!target.exists(), "the link's target was not made");
        assert!(!fs::symlink_metadata(&path).unwrap().file_type().is_symlink(), "the log is a file of its own");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_log_that_cannot_be_made_loses_lines_and_is_tried_again_later() {
        let dir = scratch("missing");
        // Its folder is a file, so the log cannot be made.
        let folder = dir.join("logs");
        fs::write(&folder, "not a folder").unwrap();
        let path = folder.join("captun-daemon.log");
        let mut log = LogFile::open(&path, 1024);
        assert!(log.file.is_none());
        assert_eq!(log.write(b"lost\n").unwrap(), 5, "the line is lost, not the event");
        assert!(log.file.is_none(), "not tried again on every line");

        fs::remove_file(&folder).unwrap();
        fs::create_dir_all(&folder).unwrap();
        let Some(long_ago) = Instant::now().checked_sub(REOPEN_EVERY) else { return };
        log.failed_at = Some(long_ago);
        log.write_all(b"kept\n").unwrap();
        log.flush().unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "kept\n");
        drop(log);
        let _ = fs::remove_dir_all(dir);
    }

    fn sent_to_guis(log: impl FnOnce()) -> Vec<LogLine> {
        let (events, mut gui) = broadcast::channel(64);
        let subscriber = tracing_subscriber::registry().with(GuiLayer::new(events).with_filter(LevelFilter::WARN));
        tracing::subscriber::with_default(subscriber, log);
        std::iter::from_fn(|| gui.try_recv().ok())
            .filter_map(|event| match event {
                Event::Log(line) => Some(line),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn guis_are_sent_warnings_and_errors_only() {
        let lines = sent_to_guis(|| {
            tracing::debug!("detail");
            tracing::info!("routine");
            tracing::warn!("worth knowing");
            tracing::error!(code = 7, "went wrong");
        });
        let seen: Vec<(LogLevel, &str)> = lines.iter().map(|l| (l.level, l.message.as_str())).collect();
        assert_eq!(seen, [(LogLevel::Warn, "worth knowing"), (LogLevel::Error, "went wrong code=7")]);
    }

    #[test]
    fn a_burst_of_warnings_reaches_guis_ten_at_a_time() {
        let lines = sent_to_guis(|| {
            for n in 0..25 {
                tracing::warn!("warning {n}");
            }
        });
        assert_eq!(lines.len(), GUI_LINES_PER_SECOND as usize);
        assert_eq!(lines[0].message, "warning 0");
    }

    #[test]
    fn guis_get_ten_lines_a_second_and_a_count_of_the_rest() {
        let start = Instant::now();
        let mut budget = Budget::new(start);
        for _ in 0..GUI_LINES_PER_SECOND {
            assert_eq!(budget.take(start), Some(0));
        }
        for _ in 0..25 {
            assert_eq!(budget.take(start + Duration::from_millis(500)), None);
        }
        let next = start + Duration::from_secs(1);
        assert_eq!(budget.take(next), Some(25), "the first line of the next second says how many were left out");
        assert_eq!(budget.take(next), Some(0));
    }
}
