# psh

Proxy by SSH => psh

## Develop before

    - Docker
    - Remote host compute
    - Config file `psh.yaml`

## psh.yaml template

```yaml
host: <remote_host>:22
user: root
password: password
server_alive_interval: 60s
rules:
  # 反向端口转发
  - remote: "<remote_ip>:27011"
    local: 127.0.0.1:3000
    reverse: true
  - remote: "<remote_ip>:28000"
    local: 127.0.0.1:3001
    reverse: true
```