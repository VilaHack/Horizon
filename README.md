# ![Horizon](assets/title.svg)
![rust-version](https://img.shields.io/badge/1.91-a?style=for-the-badge&logo=rust&logoColor=%23ffffff&label=rust&labelColor=%23f46623&color=%23555555) ![nix-version](https://img.shields.io/badge/26.05-a?style=for-the-badge&logo=nixos&logoColor=%23ffffff&label=Nix&labelColor=%237bb6e1&color=%23555555&link=https%3A%2F%2Fnixos.org%2F)

## Setup
The officially supported way to build and deploy Horizon is through Nix.

You can see a complete deployment example over at [VilaHack's infrastructure declaration's repository](https://github.com/VilaHack/Infrastructure)

### Horizon's configuration
You can find a configuration file example in the [examples directory](https://github.com/VilaHack/Horizon/tree/trunk/examples)

## Features
- [ ] Authentication
  - [ ] Sign up and log in
  - [ ] Email verification and password reset
  - [X] Session based authentication
  - [X] Access scopes
- [ ] Applications
  - [ ] Application submission
  - [ ] Application review
  - [ ] Application acceptance email
- [ ] Attendance
  - [ ] Check-in
  - [ ] Activity participation and bingo
- [ ] Teams
  - [ ] Customizable maximum team size
  - [ ] Team name, location and picture
  - [ ] Team score and evolution
- [ ] Puzzles
  - [ ] Customizable clues
  - [ ] Per puzzle file generators
  - [ ] Per puzzle flag check algorythm
  - [ ] Download files in chunks
  - [ ] Organizer help request
  - [ ] Cheating detection
  - [ ] Zero downtime puzzle updates
  - [ ] Realtime global evolution stats
- [X] Telemetry
  - [X] Usage analytics
  - [X] Logging
