import { randomUUID } from 'node:crypto';

interface SessionData {
  user: unknown;
  tokens: unknown;
  expiresAt: number;
}

export interface SessionResult {
  sessionId: string;
  user: unknown;
  expiresAt: number;
}

export default class SessionManager {
  sessions = new Map<string, SessionData>();
  duration: number;

  constructor(duration: number) {
    this.duration = duration;
  }

  create(user: unknown, tokens: unknown): SessionResult {
    const sessionId = randomUUID();
    const expiresAt = Date.now() + (this.duration * 1000);

    this.sessions.set(sessionId, { user, tokens, expiresAt });

    return { sessionId, user, expiresAt };
  }

  get(sessionId: string): SessionData | null {
    return this.sessions.get(sessionId) || null;
  }

  destroy(sessionId: string): void {
    this.sessions.delete(sessionId);
  }

  validate(sessionId: string): unknown {
    const session = this.get(sessionId);
    if (!session) return null;

    if (Date.now() >= session.expiresAt) {
      this.destroy(sessionId);
      return null;
    }

    return session.user;
  }
}
