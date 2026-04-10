declare module 'stonyx/config' {
  const config: Record<string, unknown>;
  export default config;
}

declare module 'stonyx/log' {
  const log: Record<string, ((...args: unknown[]) => void) | undefined>;
  export default log;
}

declare module 'stonyx' {
  export function waitForModule(name: string): Promise<void>;
}

declare module 'stonyx/test-helpers' {
  export function setupIntegrationTests(hooks: {
    before(fn: () => void | Promise<void>): void;
    after(fn: () => void | Promise<void>): void;
  }): void;
}
