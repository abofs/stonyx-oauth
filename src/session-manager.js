import { randomUUID } from 'node:crypto';

export default class SessionManager {
  sessions = new Map();

  constructor(duration) {
    this.duration = duration;
  }

  create(user, tokens) {
    const sessionId = randomUUID();
    const expiresAt = Date.now() + (this.duration * 1000);

    this.sessions.set(sessionId, { user, tokens, expiresAt });

    return { sessionId, user, expiresAt };
  }

  get(sessionId) {
    return this.sessions.get(sessionId) || null;
  }

  destroy(sessionId) {
    this.sessions.delete(sessionId);
  }

  validate(sessionId) {
    const session = this.get(sessionId);
    if (!session) return null;

    if (Date.now() >= session.expiresAt) {
      this.destroy(sessionId);
      return null;
    }

    return session.user;
  }
}
