import OAuthFlow from '@stonyx/oauth/oauth-flow';
import type { OAuthConfig, TokenResult } from '../../../src/oauth-flow.js';

interface MockUser {
  id: string;
  username: string;
  displayName: string;
  email: string;
}

interface NormalizedMockUser {
  id: string;
  username: string;
  displayName: string;
  avatar: null;
  email: string;
  raw: MockUser;
}

export default class MockProvider extends OAuthFlow {
  constructor(config: Omit<OAuthConfig, 'authorizationUrl' | 'tokenUrl' | 'userInfoUrl'>) {
    super({
      ...config,
      authorizationUrl: 'https://mock.provider/oauth/authorize',
      tokenUrl: 'https://mock.provider/oauth/token',
      userInfoUrl: 'https://mock.provider/api/me',
    });
  }

  async exchangeCode(_code: string): Promise<TokenResult> {
    return {
      accessToken: 'mock-access-token',
      refreshToken: 'mock-refresh-token',
      expiresIn: 3600,
    };
  }

  async fetchUserInfo(_accessToken: string): Promise<MockUser> {
    return {
      id: 'mock-user-123',
      username: 'mockuser',
      displayName: 'Mock User',
      email: 'mock@test.com',
    };
  }

  normalizeUser(rawUser: MockUser): NormalizedMockUser {
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
