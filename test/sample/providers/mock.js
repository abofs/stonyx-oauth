import OAuthFlow from '@stonyx/oauth/oauth-flow';

export default class MockProvider extends OAuthFlow {
  constructor(config) {
    super({
      ...config,
      authorizationUrl: 'https://mock.provider/oauth/authorize',
      tokenUrl: 'https://mock.provider/oauth/token',
      userInfoUrl: 'https://mock.provider/api/me',
    });
  }

  async exchangeCode(_code) {
    return {
      accessToken: 'mock-access-token',
      refreshToken: 'mock-refresh-token',
      expiresIn: 3600,
    };
  }

  async fetchUserInfo(_accessToken) {
    return {
      id: 'mock-user-123',
      username: 'mockuser',
      displayName: 'Mock User',
      email: 'mock@test.com',
    };
  }

  normalizeUser(rawUser) {
    return {
      id: rawUser.id,
      username: rawUser.username,
      displayName: rawUser.displayName,
      avatar: null,
      email: rawUser.email,
      raw: rawUser,
    };
  }
}
