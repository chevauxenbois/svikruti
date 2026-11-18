export type Kind = "EMAIL" | "IBAN" | "CARD" | "AADHAAR" | "PAN" | "IFSC" | "UPI" | "SSN" | "PHONE" | "IP";
export interface Options { kinds?: Kind[]; style?: "label" | "partial" | "hash"; key?: string }
export interface Match { kind: Kind; start: number; end: number; value: string }
export const KINDS: Kind[];
export function find(text: string, kinds?: Kind[]): Match[];
export function redact<T>(text: T, options?: Options): T;
export function redactValue<T>(value: T, options?: Options): T;
export function redactMessages<T>(messages: T[], options?: Options): T[];
export function installConsoleRedaction(options?: Options): void;
export function uninstallConsoleRedaction(): void;
export function pinoLogMethod(options?: Options): (this: unknown, args: unknown[], method: (...a: unknown[]) => void) => void;
