use std::collections::VecDeque;

/// Safely convert `Duration::as_micros()` (u128) to u64 with saturation.
#[inline]
#[allow(clippy::cast_possible_truncation)]
pub(super) fn micros_as_u64(micros: u128) -> u64 {
    micros.min(u128::from(u64::MAX)) as u64
}

/// Microsecond-precision frame timing stats for TUI performance measurement.
///
/// Uses interior mutability (`RefCell`/`Cell`) because `view(&self)` cannot
/// take `&mut self` (the `bubbletea::Model` trait requires `&self` for `view`).
/// This is safe because the TUI event loop is single-threaded.
///
/// Gated behind `PI_PERF_TELEMETRY=1` environment variable.  When disabled,
/// no `Instant::now()` calls are made — zero runtime overhead.
pub struct FrameTimingStats {
    pub(super) frame_times_us: std::cell::RefCell<VecDeque<u64>>,
    pub(super) content_build_times_us: std::cell::RefCell<VecDeque<u64>>,
    pub(super) viewport_sync_times_us: std::cell::RefCell<VecDeque<u64>>,
    pub(super) update_times_us: VecDeque<u64>,
    pub(super) total_frames: std::cell::Cell<u64>,
    pub(super) budget_exceeded_count: std::cell::Cell<u64>,
    pub(super) enabled: bool,
}

pub(super) const FRAME_TIMING_WINDOW: usize = 60;
pub(super) const FRAME_BUDGET_US: u64 = 16_667;

impl FrameTimingStats {
    pub(super) fn new() -> Self {
        let enabled =
            std::env::var_os("PI_PERF_TELEMETRY").is_some_and(|v| v == "1" || v == "true");
        Self {
            frame_times_us: std::cell::RefCell::new(VecDeque::with_capacity(FRAME_TIMING_WINDOW)),
            content_build_times_us: std::cell::RefCell::new(VecDeque::with_capacity(
                FRAME_TIMING_WINDOW,
            )),
            viewport_sync_times_us: std::cell::RefCell::new(VecDeque::with_capacity(
                FRAME_TIMING_WINDOW,
            )),
            update_times_us: VecDeque::with_capacity(FRAME_TIMING_WINDOW),
            total_frames: std::cell::Cell::new(0),
            budget_exceeded_count: std::cell::Cell::new(0),
            enabled,
        }
    }

    pub(super) fn record_frame(&self, elapsed_us: u64) {
        if !self.enabled {
            return;
        }
        let mut times = self.frame_times_us.borrow_mut();
        if times.len() >= FRAME_TIMING_WINDOW {
            times.pop_front();
        }
        times.push_back(elapsed_us);
        let total = self.total_frames.get() + 1;
        self.total_frames.set(total);
        if elapsed_us > FRAME_BUDGET_US {
            self.budget_exceeded_count
                .set(self.budget_exceeded_count.get() + 1);
        }
        if total % FRAME_TIMING_WINDOW as u64 == 0 {
            drop(times);
            self.emit_stats();
        }
    }

    pub(super) fn record_content_build(&self, elapsed_us: u64) {
        if !self.enabled {
            return;
        }
        let mut times = self.content_build_times_us.borrow_mut();
        if times.len() >= FRAME_TIMING_WINDOW {
            times.pop_front();
        }
        times.push_back(elapsed_us);
    }

    pub(super) fn record_viewport_sync(&self, elapsed_us: u64) {
        if !self.enabled {
            return;
        }
        let mut times = self.viewport_sync_times_us.borrow_mut();
        if times.len() >= FRAME_TIMING_WINDOW {
            times.pop_front();
        }
        times.push_back(elapsed_us);
    }

    pub(super) fn record_update(&mut self, elapsed_us: u64) {
        if !self.enabled {
            return;
        }
        if self.update_times_us.len() >= FRAME_TIMING_WINDOW {
            self.update_times_us.pop_front();
        }
        self.update_times_us.push_back(elapsed_us);
    }

    pub(super) fn percentiles(times: &VecDeque<u64>) -> (u64, u64, u64) {
        if times.is_empty() {
            return (0, 0, 0);
        }
        let mut sorted: Vec<u64> = times.iter().copied().collect();
        sorted.sort_unstable();
        let len = sorted.len();
        let p50 = sorted[len / 2];
        let p95 = sorted[(len * 95 / 100).min(len - 1)];
        let p99 = sorted[(len * 99 / 100).min(len - 1)];
        (p50, p95, p99)
    }

    #[allow(clippy::cast_precision_loss)]
    fn emit_stats(&self) {
        let frame = Self::percentiles(&self.frame_times_us.borrow());
        let content = Self::percentiles(&self.content_build_times_us.borrow());
        let viewport = Self::percentiles(&self.viewport_sync_times_us.borrow());
        let total = self.total_frames.get();
        let exceeded = self.budget_exceeded_count.get();
        let window = self.frame_times_us.borrow().len();
        let recent_exceeded = self
            .frame_times_us
            .borrow()
            .iter()
            .filter(|&&t| t > FRAME_BUDGET_US)
            .count();
        tracing::debug!(
            "[perf] frame p50={:.1}ms p95={:.1}ms p99={:.1}ms | \
             content p50={:.1}ms p95={:.1}ms p99={:.1}ms | \
             viewport p50={:.1}ms p95={:.1}ms p99={:.1}ms | \
             budget_exceeded={recent_exceeded}/{window} (total={exceeded}/{total})",
            frame.0 as f64 / 1000.0,
            frame.1 as f64 / 1000.0,
            frame.2 as f64 / 1000.0,
            content.0 as f64 / 1000.0,
            content.1 as f64 / 1000.0,
            content.2 as f64 / 1000.0,
            viewport.0 as f64 / 1000.0,
            viewport.1 as f64 / 1000.0,
            viewport.2 as f64 / 1000.0,
        );
    }

    #[allow(clippy::cast_precision_loss)]
    pub(super) fn summary(&self) -> String {
        if !self.enabled {
            return String::from("Frame telemetry disabled (set PI_PERF_TELEMETRY=1 to enable)");
        }
        let frame = Self::percentiles(&self.frame_times_us.borrow());
        let content = Self::percentiles(&self.content_build_times_us.borrow());
        let viewport = Self::percentiles(&self.viewport_sync_times_us.borrow());
        let update = Self::percentiles(&self.update_times_us);
        let total = self.total_frames.get();
        let exceeded = self.budget_exceeded_count.get();
        format!(
            "Frame timing (last {FRAME_TIMING_WINDOW} frames):\n  \
             view()   p50={:.1}ms  p95={:.1}ms  p99={:.1}ms\n  \
             content  p50={:.1}ms  p95={:.1}ms  p99={:.1}ms\n  \
             viewport p50={:.1}ms  p95={:.1}ms  p99={:.1}ms\n  \
             update() p50={:.1}ms  p95={:.1}ms  p99={:.1}ms\n  \
             Budget exceeded: {exceeded}/{total} frames (>{:.1}ms)",
            frame.0 as f64 / 1000.0,
            frame.1 as f64 / 1000.0,
            frame.2 as f64 / 1000.0,
            content.0 as f64 / 1000.0,
            content.1 as f64 / 1000.0,
            content.2 as f64 / 1000.0,
            viewport.0 as f64 / 1000.0,
            viewport.1 as f64 / 1000.0,
            viewport.2 as f64 / 1000.0,
            update.0 as f64 / 1000.0,
            update.1 as f64 / 1000.0,
            update.2 as f64 / 1000.0,
            FRAME_BUDGET_US as f64 / 1000.0,
        )
    }
}

/// Memory pressure level based on RSS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum MemoryLevel {
    /// RSS < 50MB — no action needed.
    Normal,
    /// 50MB <= RSS < 100MB — log warning, show in /session.
    Warning,
    /// 100MB <= RSS < 200MB — progressive tool output collapse.
    Pressure,
    /// RSS >= 200MB — truncate old messages, force degraded rendering.
    Critical,
}

impl MemoryLevel {
    pub(super) const fn from_rss_bytes(rss: usize) -> Self {
        const MB: usize = 1_000_000;
        if rss >= 200 * MB {
            Self::Critical
        } else if rss >= 100 * MB {
            Self::Pressure
        } else if rss >= 50 * MB {
            Self::Warning
        } else {
            Self::Normal
        }
    }
}

/// Abstraction for reading RSS, injectable for testing.
pub(super) trait RssReader: Send {
    fn read_rss_bytes(&self) -> Option<usize>;
}

pub(super) struct FnRssReader {
    read_fn: Box<dyn Fn() -> Option<usize> + Send>,
}

impl FnRssReader {
    pub(super) fn new(read_fn: Box<dyn Fn() -> Option<usize> + Send>) -> Self {
        Self { read_fn }
    }
}

impl RssReader for FnRssReader {
    fn read_rss_bytes(&self) -> Option<usize> {
        (self.read_fn)()
    }
}

/// Reads RSS from /proc/self/statm on Linux.
pub(super) struct ProcSelfRssReader;

/// Page size in bytes. Hardcoded to 4096 (standard for x86_64/aarch64 Linux)
/// to avoid unsafe libc::sysconf — crate uses `#![forbid(unsafe_code)]`.
const PROC_PAGE_SIZE: usize = 4096;

impl RssReader for ProcSelfRssReader {
    fn read_rss_bytes(&self) -> Option<usize> {
        #[cfg(target_os = "linux")]
        {
            // /proc/self/statm: "total_pages resident_pages shared_pages ..."
            let content = std::fs::read_to_string("/proc/self/statm").ok()?;
            let resident_pages: usize = content.split_whitespace().nth(1)?.parse().ok()?;
            Some(resident_pages * PROC_PAGE_SIZE)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }
}

/// Hysteresis threshold: stop collapsing when RSS drops below this.
pub(super) const MEMORY_RELIEF_BYTES: usize = 80_000_000;

/// Maximum messages retained when Critical truncation triggers.
pub(super) const CRITICAL_KEEP_MESSAGES: usize = 30;

/// Memory monitor that drives progressive conversation management.
pub(super) struct MemoryMonitor {
    pub(super) reader: Box<dyn RssReader>,
    pub(super) last_sample: std::time::Instant,
    pub(super) sample_interval: std::time::Duration,
    pub(super) current_rss_bytes: usize,
    pub(super) peak_rss_bytes: usize,
    pub(super) level: MemoryLevel,
    /// Index into messages vec: next tool output to collapse.
    pub(super) next_collapse_index: usize,
    /// Whether progressive collapse is in progress.
    pub(super) collapsing: bool,
    /// When the last collapse action was performed (rate-limit to 1/sec).
    pub(super) last_collapse: std::time::Instant,
    /// Whether Critical truncation has already been applied this session.
    pub(super) truncated: bool,
}

impl MemoryMonitor {
    pub(super) fn new(reader: Box<dyn RssReader>) -> Self {
        let now = std::time::Instant::now();
        Self {
            reader,
            last_sample: now,
            sample_interval: std::time::Duration::from_secs(5),
            current_rss_bytes: 0,
            peak_rss_bytes: 0,
            level: MemoryLevel::Normal,
            next_collapse_index: 0,
            collapsing: false,
            last_collapse: now,
            truncated: false,
        }
    }

    pub(super) fn new_with_reader_fn(read_fn: Box<dyn Fn() -> Option<usize> + Send>) -> Self {
        Self::new(Box::new(FnRssReader::new(read_fn)))
    }

    pub(super) fn new_default() -> Self {
        Self::new(Box::new(ProcSelfRssReader))
    }

    /// Sample RSS if the interval has elapsed. Returns true if level changed.
    pub(super) fn maybe_sample(&mut self) -> bool {
        if self.last_sample.elapsed() < self.sample_interval {
            return false;
        }
        self.last_sample = std::time::Instant::now();
        let Some(rss) = self.reader.read_rss_bytes() else {
            return false;
        };
        self.current_rss_bytes = rss;
        if rss > self.peak_rss_bytes {
            self.peak_rss_bytes = rss;
        }
        let new_level = MemoryLevel::from_rss_bytes(rss);
        let changed = new_level != self.level;
        if changed {
            match new_level {
                MemoryLevel::Warning => {
                    tracing::warn!(
                        rss_mb = rss / 1_000_000,
                        "Memory pressure: Warning level reached"
                    );
                }
                MemoryLevel::Pressure => {
                    tracing::warn!(
                        rss_mb = rss / 1_000_000,
                        "Memory pressure: Pressure level — starting progressive collapse"
                    );
                    self.collapsing = true;
                }
                MemoryLevel::Critical => {
                    tracing::error!(
                        rss_mb = rss / 1_000_000,
                        "Memory pressure: Critical level — truncating conversation"
                    );
                }
                MemoryLevel::Normal => {
                    tracing::info!(
                        rss_mb = rss / 1_000_000,
                        "Memory pressure relieved — back to Normal"
                    );
                    self.collapsing = false;
                }
            }
            self.level = new_level;
        }
        changed
    }

    /// Re-sample RSS immediately (used after collapse actions).
    pub(super) fn resample_now(&mut self) {
        if let Some(rss) = self.reader.read_rss_bytes() {
            self.current_rss_bytes = rss;
            if rss > self.peak_rss_bytes {
                self.peak_rss_bytes = rss;
            }
            self.level = MemoryLevel::from_rss_bytes(rss);
            if rss < MEMORY_RELIEF_BYTES {
                self.collapsing = false;
            }
        }
    }

    /// Format memory stats for /session display.
    #[allow(clippy::cast_precision_loss)]
    pub(super) fn summary(&self) -> String {
        let current_mb = self.current_rss_bytes as f64 / 1_000_000.0;
        let peak_mb = self.peak_rss_bytes as f64 / 1_000_000.0;
        let level_str = match self.level {
            MemoryLevel::Normal => "Normal",
            MemoryLevel::Warning => "Warning",
            MemoryLevel::Pressure => "Pressure (collapsing old outputs...)",
            MemoryLevel::Critical => "CRITICAL",
        };
        format!("Memory: {current_mb:.1}MB (peak {peak_mb:.1}MB) [{level_str}]")
    }

    /// Whether Critical-level rendering degradation should be forced.
    pub(super) const fn should_force_degraded(&self) -> bool {
        matches!(self.level, MemoryLevel::Critical)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interactive::state::{ConversationMessage, MessageRole};
    use std::collections::VecDeque;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ========================================================================
    // FrameTimingStats unit tests (PERF-3)
    // ========================================================================

    fn make_stats(enabled: bool) -> FrameTimingStats {
        FrameTimingStats {
            frame_times_us: std::cell::RefCell::new(VecDeque::new()),
            content_build_times_us: std::cell::RefCell::new(VecDeque::new()),
            viewport_sync_times_us: std::cell::RefCell::new(VecDeque::new()),
            update_times_us: VecDeque::new(),
            total_frames: std::cell::Cell::new(0),
            budget_exceeded_count: std::cell::Cell::new(0),
            enabled,
        }
    }

    #[test]
    fn frame_timing_disabled_by_default() {
        let stats = make_stats(false);
        stats.record_frame(5000);
        assert_eq!(stats.total_frames.get(), 0);
        assert!(stats.frame_times_us.borrow().is_empty());
    }

    #[test]
    fn frame_timing_records_when_enabled() {
        let stats = make_stats(true);
        stats.record_frame(5000);
        stats.record_frame(10_000);
        stats.record_frame(20_000);
        assert_eq!(stats.total_frames.get(), 3);
        assert_eq!(stats.budget_exceeded_count.get(), 1);
        assert_eq!(stats.frame_times_us.borrow().len(), 3);
    }

    #[test]
    fn frame_timing_content_build_records() {
        let stats = make_stats(true);
        stats.record_content_build(1500);
        stats.record_content_build(2500);
        assert_eq!(stats.content_build_times_us.borrow().len(), 2);
    }

    #[test]
    fn frame_timing_viewport_sync_records() {
        let stats = make_stats(true);
        stats.record_viewport_sync(800);
        stats.record_viewport_sync(1200);
        assert_eq!(stats.viewport_sync_times_us.borrow().len(), 2);
    }

    #[test]
    fn frame_timing_update_records() {
        let mut stats = make_stats(true);
        stats.record_update(500);
        stats.record_update(1000);
        assert_eq!(stats.update_times_us.len(), 2);
    }

    #[test]
    fn frame_timing_rolling_window_evicts_oldest() {
        let stats = make_stats(true);
        for i in 0..=FRAME_TIMING_WINDOW as u64 {
            stats.record_frame(i * 100);
        }
        assert_eq!(stats.frame_times_us.borrow().len(), FRAME_TIMING_WINDOW);
        assert_eq!(*stats.frame_times_us.borrow().front().unwrap(), 100);
    }

    #[test]
    fn frame_timing_percentiles_empty() {
        let empty = VecDeque::new();
        assert_eq!(FrameTimingStats::percentiles(&empty), (0, 0, 0));
    }

    #[test]
    fn frame_timing_percentiles_single_value() {
        let mut times = VecDeque::new();
        times.push_back(5000);
        assert_eq!(FrameTimingStats::percentiles(&times), (5000, 5000, 5000));
    }

    #[test]
    fn frame_timing_percentiles_known_distribution() {
        let mut times = VecDeque::new();
        for i in 1..=100 {
            times.push_back(i * 1000);
        }
        let (p50, p95, p99) = FrameTimingStats::percentiles(&times);
        assert_eq!(p50, 51_000);
        assert_eq!(p95, 96_000);
        assert_eq!(p99, 100_000);
    }

    #[test]
    fn frame_timing_summary_disabled() {
        let stats = make_stats(false);
        assert!(stats.summary().contains("disabled"));
    }

    #[test]
    fn frame_timing_summary_enabled_contains_stats() {
        let stats = make_stats(true);
        stats.record_frame(5000);
        stats.record_content_build(2000);
        let summary = stats.summary();
        assert!(summary.contains("Frame timing"));
        assert!(summary.contains("view()"));
        assert!(summary.contains("content"));
        assert!(summary.contains("viewport"));
        assert!(summary.contains("update()"));
        assert!(summary.contains("Budget exceeded"));
    }

    #[test]
    fn frame_timing_budget_exceeded_counts_correctly() {
        let stats = make_stats(true);
        stats.record_frame(10_000);
        stats.record_frame(16_000);
        stats.record_frame(FRAME_BUDGET_US);
        assert_eq!(stats.budget_exceeded_count.get(), 0);
        stats.record_frame(FRAME_BUDGET_US + 1);
        stats.record_frame(20_000);
        assert_eq!(stats.budget_exceeded_count.get(), 2);
    }

    // ========================================================================
    // MemoryMonitor unit tests (PERF-6)
    // ========================================================================

    struct MockRssReader {
        value: Arc<AtomicUsize>,
    }

    impl MockRssReader {
        fn new(initial: usize) -> (Self, Arc<AtomicUsize>) {
            let shared = Arc::new(AtomicUsize::new(initial));
            (
                Self {
                    value: Arc::clone(&shared),
                },
                shared,
            )
        }
    }

    impl RssReader for MockRssReader {
        fn read_rss_bytes(&self) -> Option<usize> {
            Some(self.value.load(Ordering::Relaxed))
        }
    }

    fn make_memory_monitor(initial_rss: usize) -> (MemoryMonitor, Arc<AtomicUsize>) {
        let (reader, shared) = MockRssReader::new(initial_rss);
        let mut monitor = MemoryMonitor::new(Box::new(reader));
        monitor.sample_interval = std::time::Duration::ZERO;
        (monitor, shared)
    }

    #[test]
    fn memory_level_classification() {
        assert_eq!(MemoryLevel::from_rss_bytes(0), MemoryLevel::Normal);
        assert_eq!(MemoryLevel::from_rss_bytes(30_000_000), MemoryLevel::Normal);
        assert_eq!(MemoryLevel::from_rss_bytes(49_999_999), MemoryLevel::Normal);
        assert_eq!(
            MemoryLevel::from_rss_bytes(50_000_000),
            MemoryLevel::Warning
        );
        assert_eq!(
            MemoryLevel::from_rss_bytes(99_999_999),
            MemoryLevel::Warning
        );
        assert_eq!(
            MemoryLevel::from_rss_bytes(100_000_000),
            MemoryLevel::Pressure
        );
        assert_eq!(
            MemoryLevel::from_rss_bytes(199_999_999),
            MemoryLevel::Pressure
        );
        assert_eq!(
            MemoryLevel::from_rss_bytes(200_000_000),
            MemoryLevel::Critical
        );
        assert_eq!(
            MemoryLevel::from_rss_bytes(500_000_000),
            MemoryLevel::Critical
        );
    }

    #[test]
    fn memory_monitor_sampling_tracks_rss_and_peak() {
        let (mut monitor, shared) = make_memory_monitor(30_000_000);
        monitor.maybe_sample();
        assert_eq!(monitor.current_rss_bytes, 30_000_000);
        assert_eq!(monitor.peak_rss_bytes, 30_000_000);
        assert_eq!(monitor.level, MemoryLevel::Normal);

        shared.store(60_000_000, Ordering::Relaxed);
        monitor.maybe_sample();
        assert_eq!(monitor.current_rss_bytes, 60_000_000);
        assert_eq!(monitor.peak_rss_bytes, 60_000_000);
        assert_eq!(monitor.level, MemoryLevel::Warning);

        shared.store(20_000_000, Ordering::Relaxed);
        monitor.maybe_sample();
        assert_eq!(monitor.current_rss_bytes, 20_000_000);
        assert_eq!(monitor.peak_rss_bytes, 60_000_000);
        assert_eq!(monitor.level, MemoryLevel::Normal);
    }

    #[test]
    fn memory_monitor_pressure_starts_collapsing() {
        let (mut monitor, shared) = make_memory_monitor(10_000_000);
        monitor.maybe_sample();
        assert!(!monitor.collapsing);

        shared.store(120_000_000, Ordering::Relaxed);
        monitor.maybe_sample();
        assert_eq!(monitor.level, MemoryLevel::Pressure);
        assert!(monitor.collapsing);
    }

    #[test]
    fn memory_monitor_hysteresis_stops_collapsing() {
        let (mut monitor, shared) = make_memory_monitor(120_000_000);
        monitor.maybe_sample();
        assert!(monitor.collapsing);

        // 70MB < 80MB relief threshold => collapsing stops.
        // Level is Warning (50-100MB), not Normal.
        shared.store(70_000_000, Ordering::Relaxed);
        monitor.resample_now();
        assert!(!monitor.collapsing);
        assert_eq!(monitor.level, MemoryLevel::Warning);

        // Drop fully below 50MB => Normal.
        shared.store(30_000_000, Ordering::Relaxed);
        monitor.resample_now();
        assert!(!monitor.collapsing);
        assert_eq!(monitor.level, MemoryLevel::Normal);
    }

    #[test]
    fn memory_monitor_summary_format() {
        let (mut monitor, _) = make_memory_monitor(55_000_000);
        monitor.maybe_sample();
        let summary = monitor.summary();
        assert!(summary.contains("55.0MB"));
        assert!(summary.contains("Warning"));
    }

    #[test]
    fn memory_monitor_should_force_degraded_only_at_critical() {
        let (mut monitor, shared) = make_memory_monitor(10_000_000);
        monitor.maybe_sample();
        assert!(!monitor.should_force_degraded());

        shared.store(60_000_000, Ordering::Relaxed);
        monitor.maybe_sample();
        assert!(!monitor.should_force_degraded());

        shared.store(150_000_000, Ordering::Relaxed);
        monitor.maybe_sample();
        assert!(!monitor.should_force_degraded());

        shared.store(250_000_000, Ordering::Relaxed);
        monitor.maybe_sample();
        assert!(monitor.should_force_degraded());
    }

    #[test]
    fn memory_progressive_collapse_ordering() {
        let messages = [
            ConversationMessage::new(MessageRole::User, "hello".into(), None),
            ConversationMessage::new(MessageRole::Tool, "output 1".into(), None),
            ConversationMessage::new(MessageRole::Assistant, "response".into(), None),
            ConversationMessage::new(MessageRole::Tool, "output 2".into(), None),
            ConversationMessage::new(MessageRole::Tool, "output 3".into(), None),
        ];
        let mut next_idx = 0usize;
        let mut found = Vec::new();
        loop {
            let result = messages[next_idx..]
                .iter()
                .enumerate()
                .find(|(_, m)| m.role == MessageRole::Tool && !m.collapsed)
                .map(|(i, _)| next_idx + i);
            match result {
                Some(idx) => {
                    found.push(idx);
                    next_idx = idx + 1;
                }
                None => break,
            }
        }
        assert_eq!(found, vec![1, 3, 4]);
    }

    #[test]
    fn memory_critical_truncation_keeps_last_messages() {
        let mut messages: Vec<ConversationMessage> = (0..50)
            .map(|i| {
                ConversationMessage::new(
                    if i % 2 == 0 {
                        MessageRole::User
                    } else {
                        MessageRole::Assistant
                    },
                    format!("msg {i}"),
                    None,
                )
            })
            .collect();

        let msg_count = messages.len();
        assert!(msg_count > CRITICAL_KEEP_MESSAGES);
        let remove_count = msg_count - CRITICAL_KEEP_MESSAGES;
        messages.drain(..remove_count);
        messages.insert(
            0,
            ConversationMessage::new(MessageRole::System, "[truncated]".into(), None),
        );

        assert_eq!(messages[0].role, MessageRole::System);
        assert!(messages[0].content.contains("truncated"));
        assert_eq!(messages.len(), CRITICAL_KEEP_MESSAGES + 1);
        assert_eq!(messages.last().unwrap().content, "msg 49");
    }

    // ========================================================================
    // Cross-platform fallback tests (PERF-CROSS-PLATFORM / bd-32sj0)
    // Verify MemoryMonitor degrades gracefully when RssReader returns None
    // (i.e. on non-Linux platforms where /proc/self/statm is unavailable).
    // ========================================================================

    /// An RssReader that always returns None — simulates non-Linux platforms.
    struct NullRssReader;

    impl RssReader for NullRssReader {
        fn read_rss_bytes(&self) -> Option<usize> {
            None
        }
    }

    fn make_null_memory_monitor() -> MemoryMonitor {
        let mut monitor = MemoryMonitor::new(Box::new(NullRssReader));
        monitor.sample_interval = std::time::Duration::ZERO;
        monitor
    }

    #[test]
    fn memory_monitor_null_reader_stays_normal() {
        let mut monitor = make_null_memory_monitor();
        // maybe_sample should return false (no level change) when reader returns None.
        assert!(!monitor.maybe_sample());
        assert_eq!(monitor.level, MemoryLevel::Normal);
        assert_eq!(monitor.current_rss_bytes, 0);
        assert_eq!(monitor.peak_rss_bytes, 0);
        assert!(!monitor.collapsing);
        assert!(!monitor.should_force_degraded());
    }

    #[test]
    fn memory_monitor_null_reader_repeated_sampling_stable() {
        let mut monitor = make_null_memory_monitor();
        // Many sampling cycles should not cause drift, panic, or state corruption.
        for _ in 0..100 {
            assert!(!monitor.maybe_sample());
        }
        assert_eq!(monitor.level, MemoryLevel::Normal);
        assert_eq!(monitor.current_rss_bytes, 0);
        assert_eq!(monitor.peak_rss_bytes, 0);
    }

    #[test]
    fn memory_monitor_null_reader_resample_now_no_panic() {
        let mut monitor = make_null_memory_monitor();
        // resample_now should silently do nothing when reader returns None.
        monitor.resample_now();
        assert_eq!(monitor.level, MemoryLevel::Normal);
        assert_eq!(monitor.current_rss_bytes, 0);
    }

    #[test]
    fn memory_monitor_null_reader_summary_shows_zero() {
        let mut monitor = make_null_memory_monitor();
        monitor.maybe_sample();
        let summary = monitor.summary();
        assert!(
            summary.contains("0.0MB"),
            "Summary should show 0.0MB when no RSS available, got: {summary}"
        );
        assert!(
            summary.contains("Normal"),
            "Summary should show Normal level when no RSS available, got: {summary}"
        );
    }

    #[test]
    fn frame_timing_operates_independently_of_memory_pressure() {
        // FrameTimingStats does not depend on MemoryMonitor or CPU pressure.
        // It should work correctly even when memory monitoring is unavailable.
        let stats = make_stats(true);
        // Simulate a realistic frame sequence.
        stats.record_frame(8_000);
        stats.record_frame(12_000);
        stats.record_frame(FRAME_BUDGET_US + 500);
        stats.record_content_build(3_000);
        stats.record_viewport_sync(1_500);
        // Verify all counters updated correctly.
        assert_eq!(stats.total_frames.get(), 3);
        assert_eq!(stats.budget_exceeded_count.get(), 1);
        assert_eq!(stats.content_build_times_us.borrow().len(), 1);
        assert_eq!(stats.viewport_sync_times_us.borrow().len(), 1);
        // Summary should produce valid output without any memory/CPU context.
        let summary = stats.summary();
        assert!(
            summary.contains("Frame timing"),
            "Summary should work without memory pressure context"
        );
        assert!(
            summary.contains("Budget exceeded: 1"),
            "Budget exceeded count should be accurate"
        );
    }

    #[test]
    fn proc_self_rss_reader_returns_some_on_linux() {
        let reader = ProcSelfRssReader;
        let result = reader.read_rss_bytes();
        #[cfg(target_os = "linux")]
        assert!(result.is_some());
        #[cfg(not(target_os = "linux"))]
        assert!(result.is_none());
    }
}
