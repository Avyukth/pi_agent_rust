use super::*;

/// Ensure the view output fits within `term_height` terminal rows.
///
/// The output must contain at most `term_height - 1` newline characters so
/// that the cursor never advances past the last visible row, which would
/// trigger terminal scrolling in the alternate-screen buffer.
pub(super) fn clamp_to_terminal_height(mut output: String, term_height: usize) -> String {
    if term_height == 0 {
        output.clear();
        return output;
    }
    let max_newlines = term_height.saturating_sub(1);

    // Fast path: count newlines and bail if we fit.
    let newline_count = memchr::memchr_iter(b'\n', output.as_bytes()).count();
    if newline_count <= max_newlines {
        return output;
    }

    // Truncate: keep only the first `max_newlines` newlines.
    let mut seen = 0usize;
    let cut = output
        .bytes()
        .position(|b| {
            if b == b'\n' {
                seen += 1;
                seen > max_newlines
            } else {
                false
            }
        })
        .unwrap_or(output.len());
    output.truncate(cut);
    output
}

pub(super) fn normalize_raw_terminal_newlines(input: String) -> String {
    if !input.contains('\n') {
        return input;
    }

    let mut out = String::with_capacity(input.len() + 16);
    let mut prev_was_cr = false;
    for ch in input.chars() {
        if ch == '\n' {
            if !prev_was_cr {
                out.push('\r');
            }
            out.push('\n');
            prev_was_cr = false;
        } else {
            prev_was_cr = ch == '\r';
            out.push(ch);
        }
    }
    out
}

impl PiApp {
    fn header_binding_hint(&self, action: AppAction, fallback: &str) -> String {
        self.keybindings
            .get_bindings(action)
            .first()
            .map_or_else(|| fallback.to_string(), std::string::ToString::to_string)
    }

    /// Render the view.
    #[allow(clippy::too_many_lines)]
    pub(super) fn view(&self) -> String {
        let view_start = if self.frame_timing.enabled {
            Some(std::time::Instant::now())
        } else {
            None
        };

        let mut output = String::new();

        // Header
        output.push_str(&self.render_header());
        output.push('\n');

        // Modal overlays (e.g. /tree) take over the main view.
        if let Some(tree_ui) = &self.tree_ui {
            output.push_str(&view_tree_ui(tree_ui, &self.styles));
            output.push_str(&self.render_footer());
            return output;
        }

        // Build conversation content for viewport.
        // Trim trailing whitespace so the viewport line count matches
        // what refresh_conversation_viewport() stored — this keeps the
        // y_offset from goto_bottom() aligned with the visible lines.
        let conversation_content = {
            let content_start = if self.frame_timing.enabled {
                Some(std::time::Instant::now())
            } else {
                None
            };
            let raw = self.build_conversation_content();
            if let Some(start) = content_start {
                self.frame_timing
                    .record_content_build(micros_as_u64(start.elapsed().as_micros()));
            }
            raw.trim_end().to_string()
        };

        // Update viewport content (we can't mutate self in view, so we render with current offset)
        // The viewport will be updated in update() when new messages arrive
        let viewport_content = if conversation_content.is_empty() {
            if self.config.quiet_startup.unwrap_or(false) {
                String::new()
            } else {
                self.styles
                    .muted_italic
                    .render("  Welcome to Pi! Type a message to begin, or /help for commands.")
            }
        } else {
            conversation_content
        };

        // Render conversation area (scrollable).
        // Use the per-frame effective height so that conditional chrome
        // (scroll indicator, tool status, status message, …) is accounted
        // for and the total output never exceeds term_height rows.
        let effective_vp = self.view_effective_conversation_height();
        let conversation_lines: Vec<&str> = viewport_content.lines().collect();
        let start = self
            .conversation_viewport
            .y_offset()
            .min(conversation_lines.len().saturating_sub(1));
        let end = (start + effective_vp).min(conversation_lines.len());
        let visible_lines = conversation_lines.get(start..end).unwrap_or(&[]);
        output.push_str(&visible_lines.join("\n"));
        output.push('\n');

        // Scroll indicator
        if conversation_lines.len() > effective_vp {
            let total = conversation_lines.len().saturating_sub(effective_vp);
            let percent = (start * 100).checked_div(total).map_or(100, |p| p.min(100));
            let indicator = format!("  [{percent}%] ↑/↓ PgUp/PgDn to scroll");
            output.push_str(&self.styles.muted.render(&indicator));
            output.push('\n');
        }

        // Tool status
        if let Some(tool) = &self.current_tool {
            let progress_str = self.tool_progress.as_ref().map_or_else(String::new, |p| {
                let secs = p.elapsed_ms / 1000;
                if secs < 1 {
                    return String::new();
                }
                let mut parts = vec![format!("{secs}s")];
                if p.line_count > 0 {
                    parts.push(format!("{} lines", format_count(p.line_count)));
                } else if p.byte_count > 0 {
                    parts.push(format!("{} bytes", format_count(p.byte_count)));
                }
                if let Some(timeout_ms) = p.timeout_ms {
                    let timeout_s = timeout_ms / 1000;
                    if timeout_s > 0 {
                        parts.push(format!("timeout {timeout_s}s"));
                    }
                }
                format!(" ({})", parts.join(" \u{2022} "))
            });
            let _ = write!(
                output,
                "\n  {} {}{} ...\n",
                self.spinner.view(),
                self.styles.warning_bold.render(&format!("Running {tool}")),
                self.styles.muted.render(&progress_str),
            );
        }

        // Status message (slash command feedback)
        if let Some(status) = &self.status_message {
            let status_style = self.styles.accent.clone().italic();
            let _ = write!(output, "\n  {}\n", status_style.render(status));
        }

        // Session picker overlay (if open)
        if let Some(ref picker) = self.session_picker {
            output.push_str(&self.render_session_picker(picker));
        }

        // Settings overlay (if open)
        if let Some(ref settings_ui) = self.settings_ui {
            output.push_str(&self.render_settings_ui(settings_ui));
        }

        // Theme picker overlay (if open)
        if let Some(ref picker) = self.theme_picker {
            output.push_str(&self.render_theme_picker(picker));
        }

        // Capability prompt overlay (if open)
        if let Some(ref prompt) = self.capability_prompt {
            output.push_str(&self.render_capability_prompt(prompt));
        }

        // Branch picker overlay (if open)
        if let Some(ref picker) = self.branch_picker {
            output.push_str(&self.render_branch_picker(picker));
        }

        // Model selector overlay (if open)
        if let Some(ref selector) = self.model_selector {
            output.push_str(&self.render_model_selector(selector));
        }

        // Input area (only when idle and no overlay open)
        if self.agent_state == AgentState::Idle
            && self.session_picker.is_none()
            && self.settings_ui.is_none()
            && self.theme_picker.is_none()
            && self.capability_prompt.is_none()
            && self.branch_picker.is_none()
            && self.model_selector.is_none()
        {
            output.push_str(&self.render_input());

            // Autocomplete dropdown (if open)
            if self.autocomplete.open && !self.autocomplete.items.is_empty() {
                output.push_str(&self.render_autocomplete_dropdown());
            }
        } else if self.agent_state != AgentState::Idle {
            // Show spinner when processing
            let _ = write!(
                output,
                "\n  {} {}\n",
                self.spinner.view(),
                self.styles.accent.render("Processing...")
            );

            if let Some(pending_queue) = self.render_pending_message_queue() {
                output.push_str(&pending_queue);
            }
        }

        // Footer with usage stats
        output.push_str(&self.render_footer());

        // Clamp the output to `term_height` rows so the terminal never
        // scrolls in the alternate-screen buffer.
        let output = clamp_to_terminal_height(output, self.term_height);
        let output = normalize_raw_terminal_newlines(output);

        if let Some(start) = view_start {
            self.frame_timing
                .record_frame(micros_as_u64(start.elapsed().as_micros()));
        }

        output
    }

    pub(super) fn render_header(&self) -> String {
        let model_label = format!("({})", self.model);

        // Branch indicator: show "Branch N/M" when session has multiple leaves.
        let branch_indicator = self
            .session
            .try_lock()
            .ok()
            .and_then(|guard| {
                let info = guard.branch_summary();
                if info.leaf_count <= 1 {
                    return None;
                }
                let current_idx = info
                    .current_leaf
                    .as_ref()
                    .and_then(|leaf| info.leaves.iter().position(|l| l == leaf))
                    .map_or(1, |i| i + 1);
                Some(format!(" [branch {current_idx}/{}]", info.leaf_count))
            })
            .unwrap_or_default();

        let model_key = self.header_binding_hint(AppAction::SelectModel, "ctrl+l");
        let next_model_key = self.header_binding_hint(AppAction::CycleModelForward, "ctrl+p");
        let prev_model_key =
            self.header_binding_hint(AppAction::CycleModelBackward, "ctrl+shift+p");
        let tools_key = self.header_binding_hint(AppAction::ExpandTools, "ctrl+o");
        let thinking_key = self.header_binding_hint(AppAction::ToggleThinking, "ctrl+t");
        let max_width = self.term_width.saturating_sub(2);

        let hints_line = truncate(
            &format!(
                "{model_key}: model  {next_model_key}: next  {prev_model_key}: prev  \
                 {tools_key}: tools  {thinking_key}: thinking"
            ),
            max_width,
        );

        let resources_line = truncate(
            &format!(
                "resources: {} skills, {} prompts, {} themes, {} extensions",
                self.resources.skills().len(),
                self.resources.prompts().len(),
                self.resources.themes().len(),
                self.resources.extensions().len()
            ),
            max_width,
        );

        format!(
            "  {} {}{}\n  {}\n  {}\n",
            self.styles.title.render("Pi"),
            self.styles.muted.render(&model_label),
            self.styles.accent.render(&branch_indicator),
            self.styles.muted.render(&hints_line),
            self.styles.muted.render(&resources_line),
        )
    }

    pub(super) fn render_input(&self) -> String {
        let mut output = String::new();

        let thinking_level = self
            .session
            .try_lock()
            .ok()
            .and_then(|guard| guard.header.thinking_level.clone())
            .and_then(|level| level.parse::<ThinkingLevel>().ok())
            .or_else(|| {
                self.config
                    .default_thinking_level
                    .as_deref()
                    .and_then(|level| level.parse::<ThinkingLevel>().ok())
            })
            .unwrap_or(ThinkingLevel::Off);

        let input_text = self.input.value();
        let is_bash_mode = parse_bash_command(&input_text).is_some();

        let (thinking_label, thinking_style, thinking_border_style) = match thinking_level {
            ThinkingLevel::Off => (
                "off",
                self.styles.muted_bold.clone(),
                self.styles.border.clone(),
            ),
            ThinkingLevel::Minimal => (
                "minimal",
                self.styles.accent.clone(),
                self.styles.accent.clone(),
            ),
            ThinkingLevel::Low => (
                "low",
                self.styles.accent.clone(),
                self.styles.accent.clone(),
            ),
            ThinkingLevel::Medium => (
                "medium",
                self.styles.accent_bold.clone(),
                self.styles.accent.clone(),
            ),
            ThinkingLevel::High => (
                "high",
                self.styles.warning_bold.clone(),
                self.styles.warning.clone(),
            ),
            ThinkingLevel::XHigh => (
                "xhigh",
                self.styles.error_bold.clone(),
                self.styles.error_bold.clone(),
            ),
        };

        let thinking_plain = format!("[thinking: {thinking_label}]");
        let thinking_badge = thinking_style.render(&thinking_plain);
        let bash_badge = is_bash_mode.then(|| self.styles.warning_bold.render("[bash]"));

        let max_width = self.term_width.saturating_sub(2);
        let reserved = 2
            + thinking_plain.chars().count()
            + if is_bash_mode {
                2 + "[bash]".chars().count()
            } else {
                0
            };
        let available_for_mode = max_width.saturating_sub(reserved);
        let mut mode_text = match self.input_mode {
            InputMode::SingleLine => "Enter: send  Shift+Enter: newline  Alt+Enter: multi-line",
            InputMode::MultiLine => "Alt+Enter: send  Enter: newline  Esc: single-line",
        }
        .to_string();
        if mode_text.chars().count() > available_for_mode {
            mode_text = truncate(&mode_text, available_for_mode);
        }
        let mut header_line = String::new();
        header_line.push_str(&self.styles.muted.render(&mode_text));
        header_line.push_str("  ");
        header_line.push_str(&thinking_badge);
        if let Some(bash_badge) = bash_badge {
            header_line.push_str("  ");
            header_line.push_str(&bash_badge);
        }
        let _ = writeln!(output, "\n  {header_line}");

        let padding = " ".repeat(self.editor_padding_x);
        let line_prefix = format!("  {padding}");
        let border_style = if is_bash_mode {
            self.styles.warning_bold.clone()
        } else {
            thinking_border_style
        };
        let border = border_style.render("│");
        for line in self.input.view().lines() {
            output.push_str(&line_prefix);
            output.push_str(&border);
            output.push(' ');
            output.push_str(line);
            output.push('\n');
        }

        output
    }

    pub(super) fn render_footer(&self) -> String {
        let total_cost = self.total_usage.cost.total;
        let cost_str = if total_cost > 0.0 {
            format!(" (${total_cost:.4})")
        } else {
            String::new()
        };

        let input = self.total_usage.input;
        let output_tokens = self.total_usage.output;
        let mode_hint = match self.input_mode {
            InputMode::SingleLine => "Shift+Enter: newline  |  Alt+Enter: multi-line",
            InputMode::MultiLine => "Enter: newline  |  Alt+Enter: send  |  Esc: single-line",
        };
        let footer_long = format!(
            "Tokens: {input} in / {output_tokens} out{cost_str}  |  {mode_hint}  |  /help  |  Ctrl+C: quit"
        );
        let footer_short = format!(
            "Tokens: {input} in / {output_tokens} out{cost_str}  |  /help  |  Ctrl+C: quit"
        );
        let max_width = self.term_width.saturating_sub(2);
        let mut footer = if footer_long.chars().count() <= max_width {
            footer_long
        } else {
            footer_short
        };
        if footer.chars().count() > max_width {
            footer = truncate(&footer, max_width);
        }
        format!("\n  {}\n", self.styles.muted.render(&footer))
    }

    /// Render a single conversation message to a string (uncached path).
    fn render_single_message(&self, msg: &ConversationMessage) -> String {
        let mut output = String::new();
        match msg.role {
            MessageRole::User => {
                let _ = write!(
                    output,
                    "\n  {} {}\n",
                    self.styles.accent_bold.render("You:"),
                    msg.content
                );
            }
            MessageRole::Assistant => {
                let _ = write!(
                    output,
                    "\n  {}\n",
                    self.styles.success_bold.render("Assistant:")
                );

                // Render thinking if present
                if self.thinking_visible {
                    if let Some(thinking) = &msg.thinking {
                        let truncated = truncate(thinking, 100);
                        let _ = writeln!(
                            output,
                            "  {}",
                            self.styles
                                .muted_italic
                                .render(&format!("Thinking: {truncated}"))
                        );
                    }
                }

                // Render markdown content
                let rendered = glamour::Renderer::new()
                    .with_style_config(self.markdown_style.clone())
                    .with_word_wrap(self.term_width.saturating_sub(6).max(40))
                    .render(&msg.content);
                for line in rendered.lines() {
                    let _ = writeln!(output, "  {line}");
                }
            }
            MessageRole::Tool => {
                // Per-message collapse: global toggle overrides, then per-message.
                let show_expanded = self.tools_expanded && !msg.collapsed;
                if show_expanded {
                    let rendered = render_tool_message(&msg.content, &self.styles);
                    let _ = write!(output, "\n  {rendered}\n");
                } else {
                    let header = msg.content.lines().next().unwrap_or("Tool output");
                    let line_count = memchr::memchr_iter(b'\n', msg.content.as_bytes()).count() + 1;
                    let summary = format!(
                        "\u{25b6} {} ({line_count} lines, collapsed)",
                        header.trim_end()
                    );
                    let _ = write!(
                        output,
                        "\n  {}\n",
                        self.styles.muted_italic.render(&summary)
                    );
                    // Show preview when per-message collapsed (not global).
                    if self.tools_expanded && msg.collapsed {
                        for (i, line) in msg.content.lines().skip(1).enumerate() {
                            if i >= TOOL_COLLAPSE_PREVIEW_LINES {
                                let remaining = line_count
                                    .saturating_sub(1)
                                    .saturating_sub(TOOL_COLLAPSE_PREVIEW_LINES);
                                let _ = writeln!(
                                    output,
                                    "  {}",
                                    self.styles
                                        .muted
                                        .render(&format!("  ... {remaining} more lines"))
                                );
                                break;
                            }
                            let _ = writeln!(
                                output,
                                "  {}",
                                self.styles.muted.render(&format!("  {line}"))
                            );
                        }
                    }
                }
            }
            MessageRole::System => {
                let _ = write!(output, "\n  {}\n", self.styles.warning.render(&msg.content));
            }
        }
        output
    }

    /// Build the conversation content string for the viewport.
    ///
    /// Uses `MessageRenderCache` (PERF-1) to avoid re-rendering unchanged
    /// messages and a conversation prefix cache (PERF-2) to skip iterating
    /// all messages during streaming. Streaming content (current_response)
    /// always renders fresh.
    pub fn build_conversation_content(&self) -> String {
        let is_streaming = !self.current_response.is_empty() || !self.current_thinking.is_empty();

        // PERF-2 fast path: during streaming, reuse the cached prefix
        // (all finalized messages) and only rebuild the streaming tail.
        if is_streaming && self.message_render_cache.prefix_valid(self.messages.len()) {
            let mut output = self.message_render_cache.prefix_get();
            self.append_streaming_tail(&mut output);
            return output;
        }

        // Full rebuild: iterate all messages with per-message cache (PERF-1).
        let mut output = String::new();

        for (index, msg) in self.messages.iter().enumerate() {
            let key =
                MessageRenderCache::compute_key(msg, self.thinking_visible, self.tools_expanded);

            if let Some(cached) = self.message_render_cache.get(index, &key) {
                output.push_str(&cached);
            } else {
                let rendered = self.render_single_message(msg);
                self.message_render_cache.put(index, key, rendered.clone());
                output.push_str(&rendered);
            }
        }

        // Snapshot the prefix for future streaming frames (PERF-2).
        self.message_render_cache
            .prefix_set(&output, self.messages.len());

        // Append streaming content if active.
        if is_streaming {
            self.append_streaming_tail(&mut output);
        }

        output
    }

    /// Render the current streaming response / thinking into `output`.
    /// Always renders fresh — never cached.
    fn append_streaming_tail(&self, output: &mut String) {
        let _ = write!(
            output,
            "\n  {}\n",
            self.styles.success_bold.render("Assistant:")
        );

        // Show thinking if present
        if self.thinking_visible && !self.current_thinking.is_empty() {
            let truncated = truncate(&self.current_thinking, 100);
            let _ = writeln!(
                output,
                "  {}",
                self.styles
                    .muted_italic
                    .render(&format!("Thinking: {truncated}"))
            );
        }

        // Show response (no markdown rendering while streaming)
        if !self.current_response.is_empty() {
            for line in self.current_response.lines() {
                let _ = writeln!(output, "  {line}");
            }
        }
    }

    pub(super) fn render_pending_message_queue(&self) -> Option<String> {
        if self.agent_state == AgentState::Idle {
            return None;
        }

        let Ok(queue) = self.message_queue.lock() else {
            return None;
        };

        let steering_len = queue.steering_len();
        let follow_len = queue.follow_up_len();
        if steering_len == 0 && follow_len == 0 {
            return None;
        }

        let max_preview = self.term_width.saturating_sub(24).max(20);

        let mut out = String::new();
        out.push_str("\n  ");
        out.push_str(&self.styles.muted_bold.render("Pending:"));
        out.push(' ');
        out.push_str(
            &self
                .styles
                .accent_bold
                .render(&format!("{steering_len} steering")),
        );
        out.push_str(&self.styles.muted.render(", "));
        out.push_str(&self.styles.muted.render(&format!("{follow_len} follow-up")));
        out.push('\n');

        if let Some(text) = queue.steering_front() {
            let preview = queued_message_preview(text, max_preview);
            out.push_str("  ");
            out.push_str(&self.styles.accent_bold.render("steering →"));
            out.push(' ');
            out.push_str(&preview);
            out.push('\n');
        }

        if let Some(text) = queue.follow_up_front() {
            let preview = queued_message_preview(text, max_preview);
            out.push_str("  ");
            out.push_str(&self.styles.muted_bold.render("follow-up →"));
            out.push(' ');
            out.push_str(&self.styles.muted.render(&preview));
            out.push('\n');
        }

        Some(out)
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn render_autocomplete_dropdown(&self) -> String {
        let mut output = String::new();

        let offset = self.autocomplete.scroll_offset();
        let visible_count = self
            .autocomplete
            .max_visible
            .min(self.autocomplete.items.len());
        let end = (offset + visible_count).min(self.autocomplete.items.len());

        // Styles
        let border_style = &self.styles.border;
        let selected_style = &self.styles.selection;
        let kind_style = &self.styles.warning;
        let desc_style = &self.styles.muted_italic;

        // Top border
        let width = 60;
        let _ = write!(
            output,
            "\n  {}",
            border_style.render(&format!("┌{:─<width$}┐", ""))
        );

        for (idx, item) in self.autocomplete.items[offset..end].iter().enumerate() {
            let global_idx = offset + idx;
            let is_selected = global_idx == self.autocomplete.selected;

            let kind_icon = match item.kind {
                AutocompleteItemKind::SlashCommand => "⚡",
                AutocompleteItemKind::ExtensionCommand => "🧩",
                AutocompleteItemKind::PromptTemplate => "📄",
                AutocompleteItemKind::Skill => "🔧",
                AutocompleteItemKind::File => "📁",
                AutocompleteItemKind::Path => "📂",
            };

            let max_label_len = width.saturating_sub(6);
            let label = if item.label.chars().count() > max_label_len {
                let mut out = item
                    .label
                    .chars()
                    .take(max_label_len.saturating_sub(1))
                    .collect::<String>();
                out.push('…');
                out
            } else {
                item.label.clone()
            };

            let line_content = format!("{kind_icon} {label:<max_label_len$}");
            let styled_line = if is_selected {
                selected_style.render(&line_content)
            } else {
                format!("{} {label:<max_label_len$}", kind_style.render(kind_icon))
            };

            let _ = write!(
                output,
                "\n  {}{}{}",
                border_style.render("│"),
                styled_line,
                border_style.render("│")
            );

            if is_selected {
                if let Some(desc) = &item.description {
                    let truncated_desc = if desc.chars().count() > width.saturating_sub(4) {
                        let mut out = desc
                            .chars()
                            .take(width.saturating_sub(5))
                            .collect::<String>();
                        out.push('…');
                        out
                    } else {
                        desc.clone()
                    };

                    let _ = write!(
                        output,
                        "\n  {}  {}{}",
                        border_style.render("│"),
                        desc_style.render(&truncated_desc),
                        border_style.render(&format!(
                            "{:>pad$}│",
                            "",
                            pad = width.saturating_sub(2).saturating_sub(truncated_desc.len())
                        ))
                    );
                }
            }
        }

        if self.autocomplete.items.len() > visible_count {
            let shown = format!(
                "{}-{} of {}",
                offset + 1,
                end,
                self.autocomplete.items.len()
            );
            let _ = write!(
                output,
                "\n  {}",
                border_style.render(&format!("│{shown:^width$}│"))
            );
        }

        let _ = write!(
            output,
            "\n  {}",
            border_style.render(&format!("└{:─<width$}┘", ""))
        );

        let _ = write!(
            output,
            "\n  {}",
            self.styles
                .muted_italic
                .render("↑/↓ navigate  Enter/Tab accept  Esc cancel")
        );

        output
    }

    #[allow(clippy::too_many_lines)]
    pub(super) fn render_session_picker(&self, picker: &SessionPickerOverlay) -> String {
        let mut output = String::new();

        let _ = writeln!(
            output,
            "\n  {}\n",
            self.styles.title.render("Select a session to resume")
        );

        let query = picker.query();
        let search_line = if query.is_empty() {
            "  > (type to filter sessions)".to_string()
        } else {
            format!("  > {query}")
        };
        let _ = writeln!(output, "{}", self.styles.muted.render(&search_line));
        let _ = writeln!(
            output,
            "  {}",
            self.styles.muted.render("─".repeat(50).as_str())
        );
        output.push('\n');

        if picker.sessions.is_empty() {
            let message = if picker.has_query() {
                "No sessions match the current filter."
            } else {
                "No sessions found for this project."
            };
            let _ = writeln!(output, "  {}", self.styles.muted.render(message));
        } else {
            let _ = writeln!(
                output,
                "  {:<20}  {:<30}  {:<8}  {}",
                self.styles.muted_bold.render("Time"),
                self.styles.muted_bold.render("Name"),
                self.styles.muted_bold.render("Messages"),
                self.styles.muted_bold.render("Session ID")
            );
            output.push_str("  ");
            output.push_str(&"-".repeat(78));
            output.push('\n');

            let offset = picker.scroll_offset();
            let visible_count = picker.max_visible.min(picker.sessions.len());
            let end = (offset + visible_count).min(picker.sessions.len());

            for (idx, session) in picker.sessions[offset..end].iter().enumerate() {
                let global_idx = offset + idx;
                let is_selected = global_idx == picker.selected;

                let prefix = if is_selected { ">" } else { " " };
                let time = crate::session_picker::format_time(&session.timestamp);
                let name = session
                    .name
                    .as_deref()
                    .unwrap_or("-")
                    .chars()
                    .take(28)
                    .collect::<String>();
                let messages = session.message_count.to_string();
                let id = crate::session_picker::truncate_session_id(&session.id, 8);

                let row = format!(" {time:<20}  {name:<30}  {messages:<8}  {id}");
                let rendered = if is_selected {
                    self.styles.selection.render(&row)
                } else {
                    row
                };

                let _ = writeln!(output, "{prefix} {rendered}");
            }

            if picker.sessions.len() > visible_count {
                let _ = writeln!(
                    output,
                    "  {}",
                    self.styles.muted.render(&format!(
                        "({}-{} of {})",
                        offset + 1,
                        end,
                        picker.sessions.len()
                    ))
                );
            }
        }

        output.push('\n');
        if picker.confirm_delete {
            let _ = writeln!(
                output,
                "  {}",
                self.styles.warning_bold.render(
                    picker
                        .status_message
                        .as_deref()
                        .unwrap_or("Delete session? Press y/n to confirm."),
                )
            );
        } else {
            let _ = writeln!(
                output,
                "  {}",
                self.styles.muted_italic.render(
                    "Type: filter  Backspace: clear  ↑/↓/j/k: navigate  Enter: select  Ctrl+D: delete  Esc/q: cancel",
                )
            );
            if let Some(message) = &picker.status_message {
                let _ = writeln!(output, "  {}", self.styles.warning_bold.render(message));
            }
        }

        output
    }

    pub(super) fn render_settings_ui(&self, settings_ui: &SettingsUiState) -> String {
        let mut output = String::new();

        let _ = writeln!(output, "\n  {}\n", self.styles.title.render("Settings"));

        if settings_ui.entries.is_empty() {
            let _ = writeln!(
                output,
                "  {}",
                self.styles.muted.render("No settings available.")
            );
        } else {
            let offset = settings_ui.scroll_offset();
            let visible_count = settings_ui.max_visible.min(settings_ui.entries.len());
            let end = (offset + visible_count).min(settings_ui.entries.len());

            for (idx, entry) in settings_ui.entries[offset..end].iter().enumerate() {
                let global_idx = offset + idx;
                let is_selected = global_idx == settings_ui.selected;

                let prefix = if is_selected { ">" } else { " " };
                let label = match *entry {
                    SettingsUiEntry::Summary => "Summary".to_string(),
                    SettingsUiEntry::Theme => "Theme".to_string(),
                    SettingsUiEntry::SteeringMode => format!(
                        "steeringMode: {}",
                        self.config.steering_queue_mode().as_str()
                    ),
                    SettingsUiEntry::FollowUpMode => format!(
                        "followUpMode: {}",
                        self.config.follow_up_queue_mode().as_str()
                    ),
                    SettingsUiEntry::QuietStartup => format!(
                        "quietStartup: {}",
                        bool_label(self.config.quiet_startup.unwrap_or(false))
                    ),
                    SettingsUiEntry::CollapseChangelog => format!(
                        "collapseChangelog: {}",
                        bool_label(self.config.collapse_changelog.unwrap_or(false))
                    ),
                    SettingsUiEntry::HideThinkingBlock => format!(
                        "hideThinkingBlock: {}",
                        bool_label(self.config.hide_thinking_block.unwrap_or(false))
                    ),
                    SettingsUiEntry::ShowHardwareCursor => format!(
                        "showHardwareCursor: {}",
                        bool_label(self.effective_show_hardware_cursor())
                    ),
                    SettingsUiEntry::DoubleEscapeAction => format!(
                        "doubleEscapeAction: {}",
                        self.config
                            .double_escape_action
                            .as_deref()
                            .unwrap_or("tree")
                    ),
                    SettingsUiEntry::EditorPaddingX => {
                        format!("editorPaddingX: {}", self.editor_padding_x)
                    }
                    SettingsUiEntry::AutocompleteMaxVisible => {
                        format!("autocompleteMaxVisible: {}", self.autocomplete.max_visible)
                    }
                };
                let row = format!(" {label}");
                let rendered = if is_selected {
                    self.styles.selection.render(&row)
                } else {
                    row
                };

                let _ = writeln!(output, "{prefix} {rendered}");
            }

            if settings_ui.entries.len() > visible_count {
                let _ = writeln!(
                    output,
                    "  {}",
                    self.styles.muted.render(&format!(
                        "({}-{} of {})",
                        offset + 1,
                        end,
                        settings_ui.entries.len()
                    ))
                );
            }
        }

        output.push('\n');
        let _ = writeln!(
            output,
            "  {}",
            self.styles
                .muted_italic
                .render("↑/↓/j/k: navigate  Enter: select  Esc/q: cancel")
        );

        output
    }

    pub(super) fn render_theme_picker(&self, picker: &ThemePickerOverlay) -> String {
        let mut output = String::new();

        let _ = writeln!(output, "\n  {}\n", self.styles.title.render("Select Theme"));

        if picker.items.is_empty() {
            let _ = writeln!(output, "  {}", self.styles.muted.render("No themes found."));
        } else {
            let offset = picker.scroll_offset();
            let visible_count = picker.max_visible.min(picker.items.len());
            let end = (offset + visible_count).min(picker.items.len());

            for (idx, item) in picker.items[offset..end].iter().enumerate() {
                let global_idx = offset + idx;
                let is_selected = global_idx == picker.selected;

                let prefix = if is_selected { ">" } else { " " };
                let (name, label) = match item {
                    ThemePickerItem::BuiltIn(name) => {
                        (name.to_string(), format!("{name} (built-in)"))
                    }
                    ThemePickerItem::File(path) => {
                        // Load theme to get name, or fallback to file stem.
                        // Performance note: repetitive load, but themes are small JSON files.
                        let name = Theme::load(path).map_or_else(
                            |_| {
                                path.file_stem().map_or_else(
                                    || "unknown".to_string(),
                                    |s| s.to_string_lossy().to_string(),
                                )
                            },
                            |t| t.name,
                        );
                        (name.clone(), format!("{name} (custom)"))
                    }
                };

                let active = name.eq_ignore_ascii_case(&self.theme.name);
                let marker = if active { " *" } else { "" };

                let row = format!(" {label}{marker}");
                let rendered = if is_selected {
                    self.styles.selection.render(&row)
                } else {
                    row
                };

                let _ = writeln!(output, "{prefix} {rendered}");
            }

            if picker.items.len() > visible_count {
                let _ = writeln!(
                    output,
                    "  {}",
                    self.styles.muted.render(&format!(
                        "({}-{} of {})",
                        offset + 1,
                        end,
                        picker.items.len()
                    ))
                );
            }
        }

        output.push('\n');
        let _ = writeln!(
            output,
            "  {}",
            self.styles
                .muted_italic
                .render("↑/↓/j/k: navigate  Enter: select  Esc/q: back")
        );

        output
    }

    pub(super) fn render_capability_prompt(&self, prompt: &CapabilityPromptOverlay) -> String {
        let mut output = String::new();

        // Title line.
        let _ = writeln!(
            output,
            "\n  {}",
            self.styles.title.render("Extension Permission Request")
        );

        // Extension and capability info.
        let _ = writeln!(
            output,
            "  {} requests {}",
            self.styles.accent_bold.render(&prompt.extension_id),
            self.styles.warning_bold.render(&prompt.capability),
        );

        // Description.
        if !prompt.description.is_empty() {
            let _ = writeln!(
                output,
                "\n  {}",
                self.styles.muted.render(&prompt.description),
            );
        }

        // Button row.
        output.push('\n');
        output.push_str("  ");
        for (idx, action) in CapabilityAction::ALL.iter().enumerate() {
            let label = action.label();
            let rendered = if idx == prompt.focused {
                self.styles.selection.render(&format!("[{label}]"))
            } else {
                self.styles.muted.render(&format!(" {label} "))
            };
            output.push_str(&rendered);
            output.push_str("  ");
        }
        output.push('\n');

        // Auto-deny timer.
        if let Some(secs) = prompt.auto_deny_secs {
            let _ = writeln!(
                output,
                "  {}",
                self.styles
                    .muted_italic
                    .render(&format!("Auto-deny in {secs}s")),
            );
        }

        // Help text.
        let _ = writeln!(
            output,
            "  {}",
            self.styles
                .muted_italic
                .render("←/→/Tab: navigate  Enter: confirm  Esc: deny")
        );

        output
    }

    pub(super) fn render_branch_picker(&self, picker: &BranchPickerOverlay) -> String {
        let mut output = String::new();

        let _ = writeln!(
            output,
            "\n  {}",
            self.styles.title.render("Select a branch")
        );
        let _ = writeln!(
            output,
            "  {}",
            self.styles
                .muted
                .render("-------------------------------------------")
        );

        if picker.branches.is_empty() {
            let _ = writeln!(
                output,
                "  {}",
                self.styles.muted_italic.render("No branches found.")
            );
        } else {
            let offset = picker.scroll_offset();
            let visible_count = picker.max_visible.min(picker.branches.len());
            let end = (offset + visible_count).min(picker.branches.len());

            for (idx, branch) in picker.branches[offset..end].iter().enumerate() {
                let global_idx = offset + idx;
                let is_selected = global_idx == picker.selected;
                let prefix = if is_selected { ">" } else { " " };

                let current_marker = if branch.is_current { " *" } else { "" };
                let msg_count = format!("({} msgs)", branch.message_count);
                let preview = if branch.preview.chars().count() > 40 {
                    let truncated: String = branch.preview.chars().take(37).collect();
                    format!("{truncated}...")
                } else {
                    branch.preview.clone()
                };

                let row = format!("{prefix} {preview:<42} {msg_count:>10}{current_marker}");
                let rendered = if is_selected {
                    self.styles.accent_bold.render(&row)
                } else if branch.is_current {
                    self.styles.accent.render(&row)
                } else {
                    self.styles.muted.render(&row)
                };
                let _ = writeln!(output, "  {rendered}");
            }
        }

        let _ = writeln!(
            output,
            "\n  {}",
            self.styles
                .muted_italic
                .render("↑/↓/j/k: navigate  Enter: switch  Esc: cancel  * = current")
        );
        output
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_raw_terminal_newlines_inserts_crlf() {
        let normalized = normalize_raw_terminal_newlines("hello\nworld\n".to_string());
        assert_eq!(normalized, "hello\r\nworld\r\n");
    }

    #[test]
    fn normalize_raw_terminal_newlines_preserves_existing_crlf() {
        let normalized = normalize_raw_terminal_newlines("hello\r\nworld\r\n".to_string());
        assert_eq!(normalized, "hello\r\nworld\r\n");
    }

    #[test]
    fn normalize_raw_terminal_newlines_handles_mixed_newlines() {
        let normalized = normalize_raw_terminal_newlines("a\r\nb\nc\r\nd\n".to_string());
        assert_eq!(normalized, "a\r\nb\r\nc\r\nd\r\n");
    }

    #[test]
    fn clamp_to_terminal_height_noop_when_fits() {
        let input = "line1\nline2\nline3".to_string();
        // 2 newlines => 3 rows; term_height=4 allows 3 newlines => fits.
        assert_eq!(clamp_to_terminal_height(input.clone(), 4), input);
    }

    #[test]
    fn clamp_to_terminal_height_truncates_excess() {
        let input = "a\nb\nc\nd\ne\n".to_string(); // 5 newlines = 6 rows
        // term_height=4 => max 3 newlines => keeps "a\nb\nc\nd"
        let clamped = clamp_to_terminal_height(input, 4);
        assert_eq!(clamped, "a\nb\nc\nd");
    }

    #[test]
    fn clamp_to_terminal_height_zero_height() {
        let clamped = clamp_to_terminal_height("hello\nworld".to_string(), 0);
        assert_eq!(clamped, "");
    }

    #[test]
    fn clamp_to_terminal_height_exact_fit() {
        // term_height=3 => max 2 newlines. Input has exactly 2 => fits.
        let input = "a\nb\nc".to_string();
        assert_eq!(clamp_to_terminal_height(input.clone(), 3), input);
    }

    #[test]
    fn clamp_to_terminal_height_trailing_newline() {
        // "a\nb\n" = 2 newlines, 3 rows (last row empty).
        // term_height=2 => max 1 newline => "a\nb"
        let clamped = clamp_to_terminal_height("a\nb\n".to_string(), 2);
        assert_eq!(clamped, "a\nb");
    }
}
