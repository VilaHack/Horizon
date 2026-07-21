mod session;
mod token;

// user document
// {
//   "auth": {
//     "email": "email",
//     "password": "argon2_hash",
//     "email_verified": boolean,
//     "created_at": "timedatetz",
//     "scopes": [ "scope", "scope" ]
//   },
//
//   ...
// }
//
// - POST /auth/register
//   { "email": "string", "password": "string" }
//   // Should look successful even if the user already exists. The client should be told something
//   // like "Verification email sent"
//
// - POST /auth/login
//   { "email": "string", "password": "string" }
//   Creates cookie
//
// - GET /auth/csrf
//   Called with the cookie
//   // Get the anti-csrf token for a given session
//
// - POST /auth/logout/current
//   Called with the cookie
//   Deletes cookie
//   // Logs out current session. Other devices will keep working
//
// - POST /auth/logout/all
//   Called with the cookie
//   Deletes cookie
//   // Logs out all devices
//
// - POST /auth/password/change
//   Called with the cookie
//   Deletes cookie
//   { "new_password": "string" }
//
// - POST /auth/password/forgot
//   { "email": "string" }
//
// - POST /auth/password/reset
//   { "token": "string", "new_password": "string" }
//
// - POST /auth/email/verify
//   { "token": "string" }
