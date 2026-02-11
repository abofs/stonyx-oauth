export default class TokenManager {
  constructor(flow) {
    this.flow = flow;
  }

  async getTokens(code) {
    const tokens = await this.flow.exchangeCode(code);
    tokens.expiresAt = Date.now() + (tokens.expiresIn * 1000);
    return tokens;
  }

  async refresh(refreshToken) {
    const tokens = await this.flow.refreshAccessToken(refreshToken);
    tokens.expiresAt = Date.now() + (tokens.expiresIn * 1000);
    return tokens;
  }

  async revoke(accessToken) {
    return this.flow.revokeToken(accessToken);
  }

  isExpired(tokenData) {
    if (!tokenData?.expiresAt) return true;
    return Date.now() >= tokenData.expiresAt;
  }
}
