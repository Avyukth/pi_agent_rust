import { basename } from "node:path";

export interface TerminalInfo {
  terminalApp?: string;
  terminalBundleId?: string;
}

export interface BackgroundNotifyConfig {
  thresholdMs: number;
  beep: boolean;
  beepSound: string;
  bringToFront: boolean;
  say: boolean;
  sayMessage: string;
}

const DEFAULT_BACKGROUND_NOTIFY_CONFIG: BackgroundNotifyConfig = {
  thresholdMs: 2000,
  beep: true,
  beepSound: "Funk",
  bringToFront: false,
  say: false,
  sayMessage: "Done in {dirname}",
};

export const BEEP_SOUNDS = ["Funk", "Pop", "Hero", "Ping", "Glass"];

export const SAY_MESSAGES = [
  "Done in {dirname}",
  "{dirname} needs your attention",
  "Task completed",
  "Build finished",
];

let terminalNotifierAvailable = false;

export async function getBackgroundNotifyConfig(ctx: any): Promise<BackgroundNotifyConfig> {
  const settings = ctx?.settingsManager?.getSettings?.() ?? {};
  const config = settings.backgroundNotify ?? {};
  return {
    ...DEFAULT_BACKGROUND_NOTIFY_CONFIG,
    ...config,
  };
}

export async function detectTerminalInfo(): Promise<TerminalInfo> {
  const env = (globalThis as any).process?.env ?? {};
  return {
    terminalApp: env.TERM_PROGRAM ?? env.COLORTERM ?? "terminal",
    terminalBundleId: env.TERM_PROGRAM,
  };
}

export async function isTerminalInBackground(_terminalInfo: TerminalInfo): Promise<boolean> {
  return true;
}

export async function checkSayAvailable(): Promise<void> {
  // no-op in conformance artifact runtime
}

export async function loadPronunciations(): Promise<void> {
  // no-op in conformance artifact runtime
}

export async function checkTerminalNotifierAvailable(): Promise<void> {
  terminalNotifierAvailable = false;
}

export async function isTerminalNotifierAvailable(): Promise<boolean> {
  return terminalNotifierAvailable;
}

export function playBeep(_sound: string): void {
  // no-op in conformance artifact runtime
}

export function displayOSXNotification(
  _message: string,
  _sound: string,
  _terminalInfo: TerminalInfo
): void {
  // no-op in conformance artifact runtime
}

export function speakMessage(_message: string): void {
  // no-op in conformance artifact runtime
}

export async function bringTerminalToFront(_terminalInfo: TerminalInfo): Promise<void> {
  // no-op in conformance artifact runtime
}

export function getCurrentDirName(): string {
  const cwd = (globalThis as any).process?.cwd?.();
  if (typeof cwd === "string" && cwd.length > 0) {
    return basename(cwd);
  }
  return "session";
}

export function replaceMessageTemplates(template: string): string {
  const dirname = getCurrentDirName();
  return template.replace(/\{dirname\}|\{session dir\}/g, dirname);
}
