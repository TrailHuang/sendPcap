# SendPcap Go 程序设计文档

## 概述

用 Go 语言重写 `send_pcap.sh`，在保留原有 pcap 文件回放功能的基础上，增加报文修改能力（MAC、VLAN、IP、端口、TTL、Protocol），并支持 IP/端口范围配置以生成多份报文组合。

## 命令行接口

```
sendpcap [flags] <file_or_directory> <target_directory> [replay_count]

Flags:
  -c, --config string        配置文件路径 (YAML)
  -q, --quiet                静默模式（目标文件不加 .osp 后缀）
  --src-mac string           源 MAC 地址
  --dst-mac string           目的 MAC 地址
  --vlan int                 VLAN ID (0 表示不修改)
  --src-ip string            源 IP 地址（单值）
  --dst-ip string            目的 IP 地址（单值）
  --src-ip-start string      源 IP 起始地址
  --src-ip-end string        源 IP 结束地址
  --dst-ip-start string      目的 IP 起始地址
  --dst-ip-end string        目的 IP 结束地址
  --src-port int             源端口（单值）
  --dst-port int             目的端口（单值）
  --src-port-start int       源端口起始值
  --src-port-end int         源端口结束值
  --dst-port-start int       目的端口起始值
  --dst-port-end int         目的端口结束值
  --ttl int                  TTL 值 (0 表示不修改)
  --protocol int             IP 协议号 (0 表示不修改)
```

## 配置结构

### YAML 配置文件示例

```yaml
src_mac: "00:11:22:33:44:55"
dst_mac: "aa:bb:cc:dd:ee:ff"
vlan: 100
src_ip: "10.0.0.1"
dst_ip: "10.0.0.2"
src_ip_start: "10.0.0.1"
src_ip_end: "10.0.0.10"
dst_ip_start: "10.0.1.1"
dst_ip_end: "10.0.1.5"
src_port_start: 10000
src_port_end: 10010
dst_port_start: 80
dst_port_end: 80
ttl: 64
protocol: 6
```

### 配置合并规则

1. 加载 YAML 配置文件（如指定）
2. 解析 CLI 参数
3. CLI 参数覆盖配置文件中的对应字段
4. 校验配置合法性

## 架构设计

### 模块划分

```
cmd/
  main.go              # 入口：参数解析、配置合并、调度执行
pkg/
  config/
    config.go          # 配置结构体、CLI 解析、YAML 加载、配置合并与校验
  modifier/
    modifier.go        # PacketModifier：报文修改核心逻辑
  generator/
    generator.go       # 组合生成器：IP/端口范围展开、临时文件管理
  processor/
    processor.go       # pcap 文件处理：读取、修改、写出
  util/
    util.go            # 工具函数：MAC/IP 解析、文件轮询、目录遍历
```

### 核心流程

```
1. 解析参数 → 合并配置 → 校验
2. 确定输入类型（文件/目录）
3. 对每个输入文件：
   a. 读取原始 pcap 作为模板（pcapgo.Reader）
   b. 根据配置计算组合数
   c. 对每个组合：修改包 → 写出临时 pcap
   d. 将临时 pcap 复制到目标目录（加 .osp 后缀，除非 --quiet）
   e. 等待目标文件被消费（轮询检查文件是否存在）
4. 清理临时目录
5. 根据 replay_count 循环或退出
```

### PacketModifier

```go
type PacketModifier struct {
    SrcMAC      net.HardwareAddr
    DstMAC      net.HardwareAddr
    VLAN        int    // 0 = 不修改
    SrcIP       net.IP // nil = 不修改
    DstIP       net.IP // nil = 不修改
    SrcPort     int    // 0 = 不修改
    DstPort     int    // 0 = 不修改
    TTL         int    // 0 = 不修改
    Protocol    int    // 0 = 不修改
}

func (m *PacketModifier) Modify(packet gopacket.Packet) ([]byte, error)
```

Modify 方法流程：
1. 解析以太网层 → 修改 MAC
2. 如需插入 VLAN → 构建 802.1Q 帧
3. 解析 IP 层 → 修改 IP/TTL/Protocol
4. 解析 TCP/UDP 层 → 修改端口
5. 序列化各层 → 返回完整数据包（校验和自动重算）

### 组合生成器

```go
type Combination struct {
    SrcIP   net.IP
    DstIP   net.IP
    SrcPort int
    DstPort int
}

func GenerateCombinations(config *Config) ([]Combination, error)
```

- 单值配置和范围配置互斥，范围优先
- 未设置的维度视为单元素（值不变）
- IP 递增：将 IP 转为 uint32，递增后再转回 net.IP
- 组合数上限警告（>10000）

### 临时文件管理

- 临时目录：`os.MkdirTemp("", "sendpcap_*")`
- 文件名：`<原始名>_<组合序号>.pcap`
- 处理完成后 `os.RemoveAll(tempDir)`
- 使用 defer 确保异常退出时也能清理

## 错误处理

| 场景 | 处理方式 |
|------|----------|
| 无效 MAC 格式 | 启动时报错退出 |
| 无效 IP 格式 | 启动时报错退出 |
| IP start > end | 启动时报错退出 |
| 端口范围无效 | 启动时报错退出 |
| 目标目录不存在 | 自动创建 (os.MkdirAll) |
| 不支持的 pcap 格式 | 跳过并记录警告 |
| 文件被占用 | 轮询等待（1ms 间隔） |
| 组合数过大 | 警告提示，继续执行 |

## 依赖

- `github.com/google/gopacket` — pcap 解析与序列化
- `github.com/google/gopacket/pcapgo` — pcap 文件读写
- `github.com/google/gopacket/layers` — 协议层定义
- `gopkg.in/yaml.v3` — YAML 配置解析
- `github.com/spf13/pflag` — CLI 参数解析（支持 GNU 风格长参数）
