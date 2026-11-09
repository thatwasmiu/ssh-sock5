# green

Keeps an SSH SOCKS5 tunnel running and reconnects by itself when your network drops. It does the job of `ssh -D`, but you only type your key's passphrase once.

## Requirements

- Go 1.26.3 or newer, only to build it. The built `green.exe` needs nothing else installed.
- An entry named `green` in `~/.ssh/config`. The name is fixed, and the entry needs `User` and `IdentityFile`:

```
Host green
    HostName 203.0.113.10
    User root
    IdentityFile ~/.ssh/my_key
```

`HostName` defaults to `green` and `Port` defaults to 22 if you leave them out.

## Build

```
git clone https://github.com/thatwasmiu/ssh-sock5.git
cd ssh-sock5
go build -o green.exe .
```

On Linux or macOS, use `go build -o green .` and run `./green`.

To run `green start` from any folder, add the project folder to your `Path`, then open a new terminal.

## Run

```
.\green.exe start
```

Enter your key's passphrase when asked. The proxy then listens on `127.0.0.1:1080`, and only your own machine can use it. To use another port:

```
.\green.exe start --port 9050
```

The first time you connect to a server that isn't in `~/.ssh/known_hosts`, green shows its fingerprint and asks whether to trust it.

Press Ctrl+C to stop.

## Use the proxy

Point any app with SOCKS5 support at `127.0.0.1:1080`. For example, in Chrome:

```
chrome.exe --proxy-server="socks5://127.0.0.1:1080"
```

## What happens when the connection drops

green checks the connection every 10 seconds and retries forever, waiting up to 30 seconds between attempts:

```
10:41:37  connection lost
10:41:39  retry 1 failed (network unreachable), next in 2s
10:41:41  retry 2 failed (network unreachable), next in 4s
10:41:45  connected to green after 3 attempts
```

The proxy port stays open during an outage, so you don't need to reconfigure anything. Requests fail until the tunnel is back, and anything already in progress, like a download, has to restart.

green stops instead of retrying if the passphrase is wrong, the server rejects your key, or the server's key has changed. A changed key can mean you're not talking to your real server, so check before removing its line from `known_hosts`.

## Test

```
go test ./...
```
