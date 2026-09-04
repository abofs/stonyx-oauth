# @stonyx/oauth Documentation

OAuth2 authentication module for the Stonyx framework. Provides a generic OAuth2 Authorization Code flow with a pluggable provider pattern.

## Contents

- [Setup & Configuration](../README.md#setup) -- installation and `config/environment.js` options
- [Routes](../README.md#routes) -- auto-registered auth endpoints
- [Supported Providers](../README.md#officially-supported-providers) -- Discord setup
- [Custom Providers](../README.md#custom-providers) -- extending `OAuthFlow` for new providers
- [Login CSRF protection](../README.md#login-csrf-protection--the-oauth_state-cookie) -- the `oauth_state` binding cookie, its attributes, and migrating a cookie-less client
- [Session Management](../README.md#session-management) -- in-memory session handling
- [Release Instructions](release.md)
