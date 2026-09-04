declare module 'node:crypto' {
  export function randomUUID(): string;

  /**
   * Structural stand-ins: this repo declares its own node shims rather than
   * depending on `@types/node`, so only the surface actually used is typed.
   */
  interface BinaryLike {
    toString(encoding: string): string;
  }

  interface Hash {
    update(data: string): Hash;
    digest(encoding: string): string;
  }

  export function randomBytes(size: number): BinaryLike;
  export function createHash(algorithm: string): Hash;
}
