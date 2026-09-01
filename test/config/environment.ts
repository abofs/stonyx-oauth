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
      }
    },
    sessionDuration: 3600,
    frontendCallbackUrl: 'http://localhost:4200/auth/callback',
  }
};
