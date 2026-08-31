declare module 'node:crypto' {
  interface Hash {
    update(data: string): Hash;
    digest(encoding: 'hex'): string;
  }

  export function randomUUID(): string;
  export function randomBytes(size: number): { toString(encoding: 'base64url' | 'hex'): string };
  export function createHash(algorithm: string): Hash;
}
