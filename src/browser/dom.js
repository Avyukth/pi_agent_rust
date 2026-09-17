function piBrowserElement(action, options) {
    "use strict";
    // Called on a resolved DOM node in a CDP isolated world. Page scripts cannot
    // replace these prototypes or intercept selector strings as executable code.
    if (!(this instanceof Element) || !this.isConnected) {
        throw new Error("Element reference is detached or does not identify an element; take a new snapshot");
    }
    const element = this;
    // File inputs are commonly hidden behind a styled upload button. Selecting
    // one is explicit, not a synthetic click; visibility is not a precondition.
    if (action === "file_input" || action === "clear_files") {
        if (!(element instanceof HTMLInputElement) || element.type !== "file") {
            throw new Error("Element is not a file input");
        }
        if (element.matches(":disabled") || element.closest("[inert]")) {
            throw new Error("File input is disabled or inert");
        }
        if (action === "clear_files") {
            // An empty DOM.setFileInputFiles list is a no-op on some Chromium
            // versions. Clearing via the native setter has explicit semantics.
            Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(element, "");
            element.dispatchEvent(new Event("input", { bubbles: true }));
            element.dispatchEvent(new Event("change", { bubbles: true }));
        }
        return {
            multiple: element.multiple,
            directory: element.webkitdirectory,
            files: Array.from(element.files).slice(0, 11).map(file => ({
                name: file.name, size: file.size
            }))
        };
    }
    const style = getComputedStyle(element);
    const rect = element.getBoundingClientRect();
    const visible = rect.width > 0 && rect.height > 0 &&
        style.visibility !== "hidden" && style.visibility !== "collapse" &&
        style.display !== "none" && Number(style.opacity) !== 0;
    if (action === "visible") return visible;
    if (action === "verify_fill") {
        return (element.isContentEditable ? element.textContent : element.value) === options.text;
    }
    if (!visible) throw new Error("Element is not visible");
    if (element.matches(":disabled") || element.closest("[inert]")) {
        throw new Error("Element is disabled or inert");
    }
    if (action === "point") {
        const left = Math.max(0, rect.left);
        const top = Math.max(0, rect.top);
        const right = Math.min(innerWidth, rect.right);
        const bottom = Math.min(innerHeight, rect.bottom);
        if (right <= left || bottom <= top) throw new Error("Element is outside the viewport");
        const x = (left + right) / 2;
        const y = (top + bottom) / 2;
        let hit = document.elementFromPoint(x, y);
        while (hit && hit.shadowRoot) {
            const inner = hit.shadowRoot.elementFromPoint(x, y);
            if (!inner || inner === hit) break;
            hit = inner;
        }
        if (!hit || (hit !== element && !element.contains(hit))) {
            throw new Error("Element is covered by another element");
        }
        return { x, y };
    }
    if (action === "focus" || action === "edit") {
        if (action === "edit") {
            const input = element instanceof HTMLInputElement;
            const textarea = element instanceof HTMLTextAreaElement;
            if ((!input && !textarea && !element.isContentEditable) ||
                (input && !["text", "search", "url", "tel", "email", "password", "number"].includes(element.type))) {
                throw new Error("Element is not a supported editable text control");
            }
            if (element.readOnly) throw new Error("Element is read-only");
        }
        element.focus();
        if (element.getRootNode().activeElement !== element) {
            throw new Error("Element could not receive focus");
        }
        if (action === "edit" && options.replace) {
            if (element.isContentEditable) {
                const range = document.createRange();
                range.selectNodeContents(element);
                const selection = getSelection();
                selection.removeAllRanges();
                selection.addRange(range);
            } else if (element instanceof HTMLInputElement && element.type === "number") {
                // Number inputs do not expose text selection. Clear through the
                // native setter, then insert the requested text through CDP.
                Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(element, "");
                element.dispatchEvent(new Event("input", { bubbles: true }));
            } else {
                element.select();
            }
        }
        return true;
    }
    throw new Error("Unknown element operation");
}
