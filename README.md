# psh

Proxy by SSH => psh

## develop guidance

- Docker
- Remote host compute
- Config file `psh.yaml`

## use guidance

  The project `psh` work like the picture, it will listen ports (define in `psh.yaml`) at `remote`
  machine and then forward traffic that comes from `client` to `local` by ssh protocol.

  ![alt struct](docs/assets/struct.png)

  You can use it by following ways:

- Define config file `psh.yaml` according to your own situation.
- You can also rename config file and by `psh -config <file_name>` to use it.
- Run binary file `psh` on macOS, Linux. (Windows is `psh.exe`)
- List more help messages by `psh -h`.
```shell
$ psh -h
Usage of psh:
  -config-dir string
        Dir of config files (default "./")
  -log-encoding string
        Log encoding format use "json" or "console" (default "console")
  -verbose int
        Show verbose logging (default 1)
  -version
        Show this program version

```

## psh.yaml template

```yaml
host: <remote_host>:22
user: root
# One of [password, identity_file] is required
password: password
#identity_file: ~/.ssh/id_rsa
# log_level is optional
log_level: 2
# log_encoding decide log print format support console or json (default value is console)
log_encoding: console
# server_alive_interval default closed
server_alive_interval: 60s
# server_alive_count_max control read, write timeout with server_alive_interval
server_alive_count_max: 3
## retry_min (default value = 1s)
#retry_min: 1s
## retry_max (default value = 60s)
#retry_max: 60s
rules:
  - remote: "<remote_ip>:27011"
    local: 127.0.0.1:3000
    reverse: true
  - remote: "<remote_ip>:28000"
    local: 127.0.0.1:3001
    reverse: true
```

## Guardian port forwarding service

1. Download `psh` and Config file `psh.yaml`
2. Create `psh` server base on `systemd` like this
```shell
$ cat /etc/systemd/system/psh.service

[Unit]
Description=Proxy by SSH
Requires=network.target
After=network.target

[Service]
Restart=on-failure
ExecStart=/usr/bin/psh -verbose 2 -config-dir /etc/psh

[Install]
WantedBy=multi-user.target
```
3. Start service is set to boot start

```shell
systemctl start psh
systemctl enable psh
```
