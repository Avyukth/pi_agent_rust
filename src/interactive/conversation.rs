use crate::model::{ContentBlock, ImageContent, TextContent, UserContent};

use super::text_utils::push_line;

pub(super) fn user_content_to_text(content: &UserContent) -> String {
    match content {
        UserContent::Text(text) => text.clone(),
        UserContent::Blocks(blocks) => content_blocks_to_text(blocks),
    }
}

pub(super) fn assistant_content_to_text(content: &[ContentBlock]) -> (String, Option<String>) {
    let mut text = String::new();
    let mut thinking = String::new();

    for block in content {
        match block {
            ContentBlock::Text(t) => text.push_str(&t.text),
            ContentBlock::Thinking(t) => thinking.push_str(&t.thinking),
            _ => {}
        }
    }

    let thinking = if thinking.trim().is_empty() {
        None
    } else {
        Some(thinking)
    };

    (text, thinking)
}

pub(super) fn content_blocks_to_text(blocks: &[ContentBlock]) -> String {
    let mut output = String::new();
    for block in blocks {
        match block {
            ContentBlock::Text(text_block) => push_line(&mut output, &text_block.text),
            ContentBlock::Image(image) => {
                let rendered =
                    crate::terminal_images::render_inline(&image.data, &image.mime_type, 72);
                push_line(&mut output, &rendered);
            }
            ContentBlock::Thinking(thinking_block) => {
                push_line(&mut output, &thinking_block.thinking);
            }
            ContentBlock::ToolCall(call) => {
                push_line(&mut output, &format!("[tool call: {}]", call.name));
            }
        }
    }
    output
}

pub(super) fn split_content_blocks_for_input(
    blocks: &[ContentBlock],
) -> (String, Vec<ImageContent>) {
    let mut text = String::new();
    let mut images = Vec::new();
    for block in blocks {
        match block {
            ContentBlock::Text(text_block) => push_line(&mut text, &text_block.text),
            ContentBlock::Image(image) => images.push(image.clone()),
            _ => {}
        }
    }
    (text, images)
}

pub(super) fn build_content_blocks_for_input(
    text: &str,
    images: &[ImageContent],
) -> Vec<ContentBlock> {
    let mut content = Vec::new();
    if !text.trim().is_empty() {
        content.push(ContentBlock::Text(TextContent::new(text.to_string())));
    }
    for image in images {
        content.push(ContentBlock::Image(image.clone()));
    }
    content
}

pub(super) fn tool_content_blocks_to_text(blocks: &[ContentBlock], show_images: bool) -> String {
    let mut output = String::new();
    let mut hidden_images = 0usize;

    for block in blocks {
        match block {
            ContentBlock::Text(text_block) => push_line(&mut output, &text_block.text),
            ContentBlock::Image(image) => {
                if show_images {
                    let rendered =
                        crate::terminal_images::render_inline(&image.data, &image.mime_type, 72);
                    push_line(&mut output, &rendered);
                } else {
                    hidden_images = hidden_images.saturating_add(1);
                }
            }
            ContentBlock::Thinking(thinking_block) => {
                push_line(&mut output, &thinking_block.thinking);
            }
            ContentBlock::ToolCall(call) => {
                push_line(&mut output, &format!("[tool call: {}]", call.name));
            }
        }
    }

    if !show_images && hidden_images > 0 {
        push_line(&mut output, &format!("[{hidden_images} image(s) hidden]"));
    }

    output
}
