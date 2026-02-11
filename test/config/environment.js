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
        module: './test/sample/providers/mock.js',
      }
    },
    sessionDuration: 3600,
  }
};
