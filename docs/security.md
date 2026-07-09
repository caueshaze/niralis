# Niralisd Security Notes

This phase intentionally builds only the daemon foundation. Authentication,
session startup, greeter management, PAM, logind integration, Wayland UI, and
privilege transitions are not implemented yet.

## Current Guarantees

- Passwords are accepted only as IPC input for the mock login path and are never
  written to logs.
- Login failure responses are generic and do not reveal whether the username or
  password was wrong.
- IPC is local-only through a Unix socket.
- The daemon creates the socket with restricted permissions (`0660`).
- Daemon, protocol, authentication, session startup, and CLI code live in
  separate crates.
- Request handling is isolated from socket handling so it can be tested without
  opening a real socket.

## Mock Authentication

`niralis-auth` currently accepts only:

- user: `test`
- password: `test`

This is a mock implementation. PAM support should be added behind the existing
`Authenticator` trait so the daemon does not need to know which authentication
backend is active.

## Mock Session Startup

`niralis-session` accepts a username and requested session, logs that a session
would be started, and returns success. It does not call `setuid`, open PAM
sessions, talk to logind, or spawn a graphical session in this phase.

## Out of Scope for Phase 1

- PAM authentication.
- Greeter process supervision.
- Wayland protocol or UI work.
- Real graphical session spawning.
- Shutdown or reboot execution.
- Attempt rate limiting and cooldown enforcement.
- Privilege dropping or user switching.
