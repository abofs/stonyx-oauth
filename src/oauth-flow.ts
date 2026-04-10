export interface OAuthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes?: string[];
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;
}

export interface TokenResult {
  accessToken: string;
  refreshToken: string | null;
  expiresIn: number;
}

export default class OAuthFlow {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scopes: string[];
  authorizationUrl: string;
  tokenUrl: string;
  userInfoUrl: string;

  constructor({ clientId, clientSecret, redirectUri, scopes, authorizationUrl, tokenUrl, userInfoUrl }: OAuthConfig) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.redirectUri = redirectUri;
    this.scopes = scopes || [];
    this.authorizationUrl = authorizationUrl;
    this.tokenUrl = tokenUrl;
    this.userInfoUrl = userInfoUrl;
  }

  buildAuthorizationUrl(stateToken: string): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: this.scopes.join(' '),
      state: stateToken,
    });

    return `${this.authorizationUrl}?${params.toString()}`;
  }

  async exchangeCode(code: string): Promise<TokenResult> {
    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: this.clientId,
        client_secret: this.clientSecret,
        grant_type: 'authorization_code',
        code,
        redirect_uri: this.redirectUri,
      }),
    });

    if (!response.ok) throw new Error(`Token exchange failed: ${response.status}`);

    const data = await response.json();

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || null,
      expiresIn: data.expires_in,
    };
  }

  async refreshAccessToken(refreshToken: string): Promise<TokenResult> {
    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: this.clientId,
        client_secret: this.clientSecret,
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
      }),
    });

    if (!response.ok) throw new Error(`Token refresh failed: ${response.status}`);

    const data = await response.json();

    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token || refreshToken,
      expiresIn: data.expires_in,
    };
  }

  async fetchUserInfo(accessToken: string): Promise<unknown> {
    const response = await fetch(this.userInfoUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });

    if (!response.ok) throw new Error(`User info fetch failed: ${response.status}`);

    return response.json();
  }

  normalizeUser(rawUser: unknown): unknown {
    return { raw: rawUser };
  }

  async revokeToken(_accessToken: string): Promise<void> {
    // Optional — providers override if supported
  }
}
