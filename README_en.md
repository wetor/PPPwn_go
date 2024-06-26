# PPPwn go

Go rewrite of [PPPwn](https://github.com/TheOfficialFloW/PPPwn). 

# Feature

- [x] Failed retry
- [x] Debug mode (more logs)
- [x] Config file
- [x] MAC whitelist
- [ ] Web front-end support for web control and log viewing

# Usage
## windows
- install [npcap](https://npcap.com/#download)
- get `stage1` and `stage2` payload
- get net interface name
 ```bash
PPPwn.exe --list
 ```
```text
[+] PPPwn - PlayStation 4 PPPoE RCE by theflow
[+] PPPwn_go - Go rewrite version by wetor
Name: "\Device\NPF_{00000000-0000-0000-0000-000000000000}", Description: "Realtek Controller"
```
- run program 
```bash
PPPwn.exe --fw="950" --interface="\Device\NPF_{00000000-0000-0000-0000-000000000000}" --stage1="stage1.bin" --stage2="stage2.bin"
```

## linux/macos
- get `stage1` and `stage2` payload
- get net interface name
 ```bash
./PPPwn --list
 ```
```text
[+] PPPwn - PlayStation 4 PPPoE RCE by theflow
[+] PPPwn_go - Go rewrite version by wetor
Name: "enp4s0", Description: ""
```
- run program
```bash
./PPPwn --fw="950" --interface="enp4s0" --stage1="stage1.bin" --stage2="stage2.bin"
```
> If this error occurs, please use `root` user or `sudo` command
> ```
> 2024/05/13 09:39:28 enp4s0: You don't have permission to perform this capture on that device (socket: Operation not permitted
> ```

## Config file (optional)
`--config=config.yaml` Using configuration file, [sample](configs/config_example.yaml)

config.yaml
```yaml
interface: enp4s0
injects:
    target_mac:
    firmware: 1100
    stage1_file: stage1/stage1.bin
    stage2_file: stage2/stage2.bin
```
run program
```bash
./PPPwn --config="config.yaml"
```

## Whitelist MAC address (optional)
`--target_mac="C8:23:41:41:41:41"` Inject only this PS4 mac address, empty attempts to inject all devices

## Receive timeout (optional)
`--receive_timeout=30` Main steps timeout second
  - `[*] Waiting for LCP configure request... (wait 30s)`
  - `[*] Waiting for LCP configure reject... (wait 30s)`
  - `[*] Defeating KASLR... (wait 30s)`

## Auto retry (optional)
- `--retry` Enable auto retry, automatically retry after failure
- `--retry_wait=5` Automatic retry wait time after failure

## Debug mode (optional)
- `--debug` Enable debug mode, more information will be output  
- `--log="log.log"` All outputs will be written to the log file

# Build
## windows
- install [npcap](https://npcap.com/dist/npcap-1.79.exe)
```bash
set CGO_ENABLED=0
go build -o PPPwn.exe cmd/main.go 
```

## linux/macos
- install `libpcap-dev`
```bash
CGO_ENABLED=1 go build -o PPPwn cmd/main.go 
```

# Improved
- `Scanning for corrupted object`  execution is too slow


# Reference
- [PPPwn](https://github.com/TheOfficialFloW/PPPwn): Exploit  
- [zouppp](https://github.com/hujun-open/zouppp): The related structures of `LCP` and `PPPoE` , as well as the decoder and Serializer  
- [pppoe-hijack-go](https://github.com/LuckyC4t/pppoe-hijack-go): Example of using `gopacket`  
- [PPPwn_cpp](https://github.com/xfangfang/PPPwn_cpp): cross compile `libpcap` using zig in workflows and udp payload fragment

Thanks to Andy's wonderful magic  