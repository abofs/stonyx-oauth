declare module '@stonyx/rest-server' {
  export class Request {
    constructor();
  }

  export default class RestServer {
    static instance: RestServer;
    static close(): void;
    mountRoute(RequestClass: unknown, options: { name: string; options?: unknown }): void;
  }
}
