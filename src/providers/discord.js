import OAuthFlow from '../oauth-flow.js';

export default class DiscordProvider extends OAuthFlow {
  constructor(config) {
    super({
      ...config,
      authorizationUrl: 'https://discord.com/oauth2/authorize',
      tokenUrl: 'https://discord.com/api/oauth2/token',
      userInfoUrl: 'https://discord.com/api/users/@me',
    });
  }

  async exchangeCode(code) {
    const response = await fetch(this.tokenUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
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

  normalizeUser(rawUser) {
    const { id, username, global_name, avatar, email } = rawUser;

    return {
      id,
      username,
      displayName: global_name || username,
      avatar: avatar ? `https://cdn.discordapp.com/avatars/${id}/${avatar}.png` : null,
      email: email || null,
      raw: rawUser,
    };
  }
}
