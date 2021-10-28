# psh

Proxy by SSH => psh

## develop guidance

  - Docker
  - Remote host compute
  - Config file `psh.yaml`

## use guidance

  - Run binary file (`psh`)
  - list help message by `psh -h`

## psh.yaml template

```yaml
host: <remote_host>:22
user: root
# One of [password, identity_file] is required
password: password
server_alive_interval: 60s
# log_level is optional
log_level: 2
rules:
  # 反向端口转发
  - remote: "<remote_ip>:27011"
    local: 127.0.0.1:3000
    reverse: true
  - remote: "<remote_ip>:28000"
    local: 127.0.0.1:3001
    reverse: true
```