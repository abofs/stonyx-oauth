import type OAuthFlow from './oauth-flow.js';
import type { TokenResult } from './oauth-flow.js';

export interface TokenData extends TokenResult {
  expiresAt: number;
}

export default class TokenManager {
  flow: OAuthFlow;

  constructor(flow: OAuthFlow) {
    this.flow = flow;
  }

  async getTokens(code: string): Promise<TokenData> {
    const tokens = await this.flow.exchangeCode(code) as TokenData;
    tokens.expiresAt = Date.now() + (tokens.expiresIn * 1000);
    return tokens;
  }

  async refresh(refreshToken: string): Promise<TokenData> {
    const tokens = await this.flow.refreshAccessToken(refreshToken) as TokenData;
    tokens.expiresAt = Date.now() + (tokens.expiresIn * 1000);
    return tokens;
  }

  async revoke(accessToken: string): Promise<void> {
    return this.flow.revokeToken(accessToken);
  }

  isExpired(tokenData: { expiresAt?: number } | null | undefined): boolean {
    if (!tokenData?.expiresAt) return true;
    return Date.now() >= tokenData.expiresAt;
  }
}
