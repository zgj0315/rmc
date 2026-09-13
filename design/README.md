# 界面画板

`docs/方案设计.md` 第 3.10 节界面的画板源文件，八个状态各一块，发布为 Claude Design 画布供评审。

## 文件

| 文件 | 作用 |
|---|---|
| `_shell_head.txt` | 共用样式与 Design Component 文件头 |
| `body-<State>.html` | 单个状态的正文片段，只包含窗口内容区 |
| `build.mjs` | 把文件头、窗口外框（标题栏与页签）和正文拼成 `<State>.dc.html` |
| `canvas.json` | 画板在画布上的位置、标题与便签 |

`<State>.dc.html` 和最终发布的画布页面都是生成物，不入库，改动只提交上表中的文件。

## 状态

未开启 `Main`、预检中 `Preflight`、已连接 `Connected`、一体机不可达 `Degraded`、正在重连 `Backoff`、认证失败 `AuthFailed`，以及诊断页 `Diagnostics` 与日志页 `Logs`。

窗口固定 520×720，配色取 Windows 11 Fluent 语义色。

## 重新生成

```
cd design && node build.mjs
```

之后用 Claude Code 的 `/design` 技能把八个 `.dc.html` 与 `canvas.json` 重新打包并发布到原画布链接。
