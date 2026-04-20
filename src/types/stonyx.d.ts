declare module 'stonyx/config' {
  interface OAuthConfig {
    providers: Record<string, { module?: string; [key: string]: unknown }>;
    sessionDuration: number;
    frontendCallbackUrl?: string;
    logColor?: string;
    logMethod?: string;
  }
  interface Config {
    oauth: OAuthConfig;
    rootPath: string;
    [key: string]: unknown;
  }
  const config: Config;
  export default config;
}

declare module 'stonyx/log' {
  interface Log {
    oauth(message: string): void;
    defineType(type: string, setting: string, options?: Record<string, unknown> | null): void;
    [key: string]: unknown;
  }
  const log: Log;
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
