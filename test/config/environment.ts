export default {
  restServer: {
    dir: './test/sample/requests',
  },
  oauth: {
    providers: {
      mock: {
        clientId: 'test-client-id',
        clientSecret: 'test-client-secret',
        redirectUri: 'http://localhost:2666/auth/callback/mock',
        scopes: ['identify'],
        module: './test/sample/providers/mock.ts',
      },
      // Second provider entry wired to the same mock module. Exists so the
      // suite can prove a state issued for one provider is rejected at
      // another provider's callback (#36, AC 2).
      mock2: {
        clientId: 'test-client-id-2',
        clientSecret: 'test-client-secret-2',
        redirectUri: 'http://localhost:2666/auth/callback/mock2',
        scopes: ['identify'],
        module: './test/sample/providers/mock.ts',
      }
    },
    sessionDuration: 3600,
    frontendCallbackUrl: 'http://localhost:4200/auth/callback',
  }
};
