# Lanboat All-in-One

[简体中文](README.md) · **English**

Lanboat All-in-One is a lightweight networking tool that provides proxy client and server support, TUN, DNS, and traffic routing in a single executable. Use it to run a local proxy, host a remote proxy, or route system traffic.

## Features

- **Client and server in one executable.** Choose the role in your configuration. You can run multiple inbounds and outbounds at the same time.
- **Multiple protocols.** Shadowsocks, VMess, VLESS, Trojan, Hysteria, Hysteria2, TUIC, SOCKS5, HTTP/HTTPS, WireGuard, SSH, Brook, and more.
- **Policy-based routing.** Proxy, allow direct connections, or reject traffic based on domains, IP addresses, ports, and rule sets. Proxy groups are supported.
- **DNS management.** UDP, TCP, encrypted DNS, FakeIP, caching, and domain-specific resolution.
- **TUN mode.** Route system traffic without configuring each application separately.

Run `lanboat-allinone protocols` for the full protocol list. See the [user guide](docs/README.md) and [example configurations](examples) to get started.

## Install

Download the executable for your operating system and architecture from [GitHub Releases](https://github.com/zatxm/lanboat-allinone/releases). Each download is an executable file.

| Operating system | Architecture | File |
| --- | --- | --- |
| Windows | amd64, arm64 | `.exe` executable |
| Linux | amd64, arm64 | Native executable |
| macOS | Intel amd64, Apple Silicon arm64 | Native executable |

On Linux and macOS, make the downloaded file executable with `chmod +x filename` before running it. See [Downloading, verifying, and running](docs/releases.md).

To build from source with Go 1.27.4 or later, run these commands from a terminal.

```bash
git clone https://github.com/zatxm/lanboat-allinone.git
cd lanboat-allinone
bash scripts/build.sh
./build/lanboat-allinone version
```

The executable is created at `build/lanboat-allinone`. You can move it to any directory. To build on Windows, run the following command from the repository directory.

```powershell
go build -trimpath -ldflags "-s -w" -o lanboat-allinone.exe ./cmd/lanboat-allinone
```

Linux is the primary platform for testing. See [TUN mode](docs/tun.md) for the permissions, drivers, and system requirements on Windows and macOS.

## Run as a client

Copy the [client example](examples/independent-client.json), fill in your server address, port, and password, then check and run the configuration.

```bash
cp examples/independent-client.json client.json
./build/lanboat-allinone check -c client.json
./build/lanboat-allinone client -c client.json
```

The example provides SOCKS5 and HTTP proxies on `127.0.0.1:1080`. Set your application’s proxy host to `127.0.0.1` and port to `1080`.

Press `Ctrl+C` to stop. Configure each application’s proxy manually or use [TUN mode](docs/tun.md) for system traffic.

## Run as a server

Copy the [server example](examples/independent-server.json), set the protocol, listening address, port, and password, then check and run the configuration.

```bash
cp examples/independent-server.json server.json
./build/lanboat-allinone check -c server.json
./build/lanboat-allinone server -c server.json
```

The example listens on localhost. To accept remote connections, set `listen` to the server’s address or `0.0.0.0`, allow the corresponding TCP or UDP ports through the firewall, and replace the sample password with a randomly generated password.

TLS-based protocols such as Hysteria2 also require a certificate. See [Client and server setup](docs/client-server.md).

## Common commands

| Command | What it does |
| --- | --- |
| `version` | Show the version |
| `protocols` | List protocols and capabilities |
| `check -c config.json` | Validate the configuration |
| `run -c config.json` | Start with the given configuration |
| `client -c client.json` | Start with the client configuration |
| `server -c server.json` | Start with the server configuration |
| `help` | Show command help |

`run`, `client`, and `server` accept the same configuration format. The inbounds, outbounds, and routing rules determine how the application runs.

## User guides

The detailed guides are in Chinese.

- [Client and server setup](docs/client-server.md) covers local proxies, remote connections, Hysteria2, and certificates.
- [Configuration](docs/configuration.md) covers listening addresses, outbounds, logs, and data files.
- [DNS and routing](docs/dns-routing.md) covers resolvers, routing, rule sets, and proxy groups.
- [TUN mode](docs/tun.md) covers system traffic, supported platforms, and permissions.
- [Protocols and examples](docs/protocols.md) provides example configurations by protocol.
- [Troubleshooting](docs/troubleshooting.md) covers configuration errors, connection failures, and logs.
- [Downloading and running](docs/releases.md) explains how to select, verify, and run a release executable.

When reporting an issue, include the version, operating system, relevant logs, and a redacted configuration. Remove passwords, private keys, authentication keys, and access tokens.
