# rmc

Remote Maintenance Client：现场人员在笔记本上开启远程维护，公司的远程工程师经
运维服务器登录到客户内网里的一体机。

![原理图：笔记本主动拨出隧道，工程师的 SSH 沿隧道进入客户内网直达一体机](docs/原理图.svg)

| 想做什么 | 看这里 |
|---|---|
| 使用客户端、远程连入、排查问题 | [`docs/使用手册.md`](docs/使用手册.md) |
| 部署运维服务器、开通与吊销账号 | [`docs/运维服务器部署.md`](docs/运维服务器部署.md) |
| 了解整体设计 | [`docs/方案设计.md`](docs/方案设计.md) |
| Windows 真机验收 | [`docs/windows-验收清单.md`](docs/windows-验收清单.md) |
| 还没做完的事 | [`docs/交付前还剩什么.md`](docs/交付前还剩什么.md) |
| 执行期间的裁决记录 | [`docs/superpowers/ledgers/`](docs/superpowers/ledgers/README.md) |

Windows 便携包（`rmc.exe`）由 GitHub Actions 的 `app` 工作流产出，见其
`rmc-portable` 产物。运维服务器的 Linux 静态二进制（`rmc-gateway`）由 `core`
工作流产出，见其 `rmc-gateway-linux-x86_64` 产物。
