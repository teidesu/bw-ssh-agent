# bw-ssh-agent

finally, an ssh-agent for bitwarden. currenly macos only.

stores the bitwarden auth info in secure enclave, and decrypts them on the fly

## build

to access secure enclave, apple requires a provisioning profile.
to get one, use xcode to build an empty app with the correct entitlements, and then yoink 
the `embedded.provisionprofile` file from the build folder into `assets/`.
for a full guide, see [entitlements-guide.md](docs/entitlements-guide.md)

you also need to fill in the `.env` file with the signing identity and team id.

to run the app in the debug mode locally, use `cargo make run <args>`

**build profiles**

- development: `cargo make build`
- production: `cargo make --profile production build`

## usage

bw-ssh-agent only exposes the keys that have the `desu.tei.bw-ssh-agent:expose` field set to `true`.

```bash
# first login to bitwarden
bw-ssh-agent login

# start the daemon
bw-ssh-agent daemon start &

# now you can use the agent to ssh
SSH_AUTH_SOCK=~/Library/Application\ Support/bw-ssh-agent/agent.sock ssh -F none 1.2.3.4
```

you can register the daemon as a MacOS service. it will then run in the background and start when you log in to the user

```bash
bw-ssh-agent daemon register
```

1password provides [extensive documentation](https://developer.1password.com/docs/ssh/agent/compatibility) on configuring different clients to use SSH agent

## todo

- think of a way to avoid having to access tpm for every connection 
  - maybe temporarily store the decrypted symmetric key in memory?
- improve bitwarden auth support (currently only pbkdf2 is supported, and 2fa is not supported)
- add support for other operating systems

## acknowledgements

- [sekey](https://github.com/sekey/sekey) and [ntrippar/ssh-agent](https://github.com/ntrippar/ssh-agent) (MIT) - ssh-agent implementation is heavily based on their work
- [rubywarden](https://github.com/jcs/rubywarden/blob/master/API.md) - bitwarden api implementation is based on their work

## license

MIT license