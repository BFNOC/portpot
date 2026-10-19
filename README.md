# portpot

[![ci](https://github.com/BFNOC/portpot/actions/workflows/ci.yml/badge.svg)](https://github.com/BFNOC/portpot/actions/workflows/ci.yml)

打印机蜜罐。同时绑定 `0.0.0.0` 和 `::` 的任意端口，模拟打印机服务并正常回应，双向每个字节都记入日志，另附 Web 页面辅助查看。支持 Windows / macOS / Linux。

## 安装

- 下载 [Releases](https://github.com/BFNOC/portpot/releases) 里对应平台的二进制，`SHA256SUMS` 可校验
- 或 `go install github.com/BFNOC/portpot@latest`

## 用法

```
portpot [-l 端口/协议,...] [-model 型号] [-log 文件] [-web 地址]
```

不带 `-l` 时默认 `80/http,443/https,9100/pjl,161/snmp`。

| 协议 | 层 | 行为 |
|------|----|------|
| `raw`（默认） | TCP | 只收不回 |
| `pjl` | TCP | 应答 `@PJL INFO ID/STATUS/PRODINFO/FILESYS`、`ECHO` 等，打印数据照收 |
| `http` | TCP | `/` 返回伪造状态页，其他路径 404 |
| `https` | TCP | 自签证书 TLS，内部同 `http`；握手失败时记录原始字节 |
| `udp` | UDP | 只收不回 |
| `snmp` | UDP | v1/v2c，Get/GetNext/GetBulk；community 不对或为 v3 时只记不回 |

示例：

```
sudo ./portpot -l 9100/pjl,443/https,161/snmp -l 515,631/http -model "HP LaserJet Pro M404dn"
```

| 参数 | 默认 | 说明 |
|------|------|------|
| `-model` | `HP LaserJet Pro M404dn` | PJL/HTTP/SNMP/证书里显示的型号，改成真打印机的型号更像 |
| `-community` | `public` | 应答的 SNMP community |
| `-log` | `portpot.log` | 全量日志，每个数据块带 hexdump，追加写 |
| `-web` | `127.0.0.1:8088` | Web 查看器地址，空字符串关闭 |
| `-cert` / `-key` | `portpot.crt` / `portpot.key` | 不存在则生成自签证书，之后复用，指纹保持不变 |

控制台每个事件输出一行摘要（OPEN / IN / OUT / NOTE / CLOSE），完整内容在日志文件和 Web 页面里看。

## 部署：接管打印机 IP

1. 断开打印机网络。
2. 把本机静态 IP 设成打印机原 IP，掩码和网关保持一致。
3. 以管理员身份运行：
   - Linux：`sudo ./portpot`，或 `sudo setcap cap_net_bind_service=+ep ./portpot` 后普通用户运行
   - macOS：`sudo ./portpot`
   - Windows：管理员终端运行，首次运行时防火墙弹窗选允许（专用和公用网络都勾上）
4. 浏览器打开 `http://127.0.0.1:8088/`。

Windows 下的常见端口冲突：80/443 可能被 IIS 或 http.sys 占用，161 被"SNMP 服务"占用，需先停掉。另外可能撞上 Hyper-V 保留的端口段，用 `netsh int ipv4 show excludedportrange tcp` 查看。绑定失败时控制台会打印 `FAIL listen ...` 和原因提示，其余端口继续运行。

## 注意

- Web 页面里是攻击方发来的原始数据，默认只监听 127.0.0.1。不要改成对外监听。
- 全部会话都保存在内存里供 Web 查看，长时间运行时内存会持续增长。
- UDP 一个包算一个会话，一次 snmpwalk 会产生很多条记录。

## 构建

```
go build -o portpot .
GOOS=windows GOARCH=amd64 go build -o portpot.exe .
GOOS=darwin  GOARCH=arm64 go build -o portpot-mac .
go test ./...
```

CI：每次 push 到 main 和每个 PR 都会在 Linux / Windows / macOS 上跑 gofmt、vet、test。推送 `v*` tag 时自动构建 6 个平台的二进制并发布到 Releases：

```
git tag v0.1.0 && git push origin v0.1.0
```
