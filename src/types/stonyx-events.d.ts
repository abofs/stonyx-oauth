declare module '@stonyx/events' {
  export function setup(events: string[]): void;
  export function emit(event: string, ...args: unknown[]): Promise<void>;
}
