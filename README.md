# PPPwn go
[[English]](README_en.md)

使用Go语言实现的[PPPwn](https://github.com/TheOfficialFloW/PPPwn). 

# 特性

- [x] 失败重试
- [x] 调试模式（更多日志）
- [x] 配置文件
- [x] MAC白名单
- [ ] WEB前端控制和日志显示

# Usage
## windows
- 安装 [npcap](https://npcap.com/#download)
- 获取 `stage1` 和 `stage2` 文件
- 获取当前设备网卡名
 ```bash
PPPwn.exe --list
 ```
```text
[+] PPPwn - PlayStation 4 PPPoE RCE by theflow
[+] PPPwn_go - Go rewrite version by wetor
Name: "\Device\NPF_{00000000-0000-0000-0000-000000000000}", Description: "Realtek Controller"
```
- 运行PPPwn
```bash
PPPwn.exe --fw="950" --interface="\Device\NPF_{00000000-0000-0000-0000-000000000000}" --stage1="stage1.bin" --stage2="stage2.bin"
```

## linux/macos
- 获取 `stage1` 和 `stage2` 文件
- 获取当前设备网卡名
 ```bash
./PPPwn --list
 ```
```text
[+] PPPwn - PlayStation 4 PPPoE RCE by theflow
[+] PPPwn_go - Go rewrite version by wetor
Name: "enp4s0", Description: ""
```
- 运行PPPwn
```bash
./PPPwn --fw="950" --interface="enp4s0" --stage1="stage1.bin" --stage2="stage2.bin"
```
> 如果提示以下错误，请使用`root`用户或`sudo`命令
> ```
> 2024/05/13 09:39:28 enp4s0: You don't have permission to perform this capture on that device (socket: Operation not permitted
> ```

## 配置文件 (可选)
`--config=config.yaml` 使用配置文件启动，[样例](configs/config_example.yaml)

config.yaml
```yaml
interface: enp4s0
injects:
    target_mac:
    firmware: 1100
    stage1_file: stage1/stage1.bin
    stage2_file: stage2/stage2.bin
```
- 运行PPPwn
```bash
./PPPwn --config="config.yaml"
```

## MAC白名单 (可选)
`--target_mac="C8:23:41:41:41:41"` 仅注入指定MAC地址的PS4，为空则尝试所有设备

## 接受消息最大等待时间 (可选)
`--receive_timeout=30` 主要步骤等待时间，秒
  - `[*] Waiting for LCP configure request... (wait 30s)`
  - `[*] Waiting for LCP configure reject... (wait 30s)`
  - `[*] Defeating KASLR... (wait 30s)`

## 失败重试 (可选)
- `--retry` 开启时，失败后会自动重试
- `--retry_wait=5` 自动重试等待时间，秒

## 调试模式 (可选)
- `--debug` 开启调试模式，会显示更多日志  
- `--log="log.log"` 日志储存到文件，为空则不保存到文件

# 编译
## windows
- 安装 [npcap](https://npcap.com/dist/npcap-1.79.exe)
```bash
set CGO_ENABLED=0
go build -o PPPwn.exe cmd/main.go 
```

## linux/macos
- 安装 `libpcap-dev`
```bash
CGO_ENABLED=1 go build -o PPPwn cmd/main.go 
```

# 待改进
- `Scanning for corrupted object` 执行较慢


# Reference
- [PPPwn](https://github.com/TheOfficialFloW/PPPwn): 漏洞实现  
- [zouppp](https://github.com/hujun-open/zouppp): `LCP` 和 `PPPoE`的结构，以及解码器和序列化器实现 
- [pppoe-hijack-go](https://github.com/LuckyC4t/pppoe-hijack-go): `gopacket`使用样例
- [PPPwn_cpp](https://github.com/xfangfang/PPPwn_cpp): 在workflows中使用zig交叉编译`libpcap`和udp分片发包实现

Thanks to Andy's wonderful magic  