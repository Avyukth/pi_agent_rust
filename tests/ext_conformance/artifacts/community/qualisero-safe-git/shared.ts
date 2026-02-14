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

export async function checkSayAvailable(): Promise<void> {
  // no-op in conformance artifact runtime
}

export async function loadPronunciations(): Promise<void> {
  // no-op in conformance artifact runtime
}

export async function checkTerminalNotifierAvailable(): Promise<void> {
  // no-op in conformance artifact runtime
}

export async function notifyOnConfirm(_message: string): Promise<void> {
  // no-op in conformance artifact runtime
}

export async function bringTerminalToFront(_terminalInfo: TerminalInfo): Promise<void> {
  // no-op in conformance artifact runtime
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
