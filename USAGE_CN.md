# OpenClaw 指纹扫描器 - 快速上手指南

[English](USAGE.md) | [简体中文](USAGE_CN.md)

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 基础扫描

```bash
# 扫描单个IP
python scanner.py -t 192.168.1.100

# 扫描C段
python scanner.py -t 192.168.1.0/24

# 扫描指定端口
python scanner.py -t 192.168.1.100:8080
```

## 常用场景

### 场景1：快速扫描C段

```bash
python scanner.py -t 192.168.1.0/24 --realtime -w 50
```

- `--realtime`: 实时显示发现的目标
- `-w 50`: 使用50个并发线程

### 场景2：批量扫描多个网段

创建目标文件 `targets.txt`:
```
192.168.1.0/24
10.0.0.0/24
172.16.0.0/28
```

执行扫描:
```bash
python scanner.py -f targets.txt --realtime -o results.json --stats
```

### 场景3：隐蔽扫描

**什么是隐蔽扫描？**

隐蔽扫描是指降低扫描活动的可见性，避免被目标系统的安全设备（IDS/IPS、WAF、防火墙）检测到。

**为什么需要隐蔽扫描？**
- 避免触发安全告警
- 避免IP被封禁
- 避免影响目标服务性能
- 满足渗透测试合规要求

**隐蔽扫描命令：**
```bash
python scanner.py -t 192.168.1.0/24 -w 5 --rate-limit 2 --timeout 10
```

**参数说明：**
- `-w 5`: 低并发（5个线程，而不是50个）
- `--rate-limit 2`: 每个请求间隔2秒（模拟正常访问）
- `--timeout 10`: 长超时（更有耐心）

**对比：**
```bash
# 快速扫描（容易被发现）
python scanner.py -t 192.168.1.0/24 -w 100 --timeout 3
# 特征：短时间大量请求，明显的扫描行为

# 隐蔽扫描（不易被发现）
python scanner.py -t 192.168.1.0/24 -w 5 --rate-limit 2 --timeout 10
# 特征：流量分散，像正常用户访问
```

### 场景4：高置信度筛选

```bash
python scanner.py -f targets.txt --min-confidence HIGH -o high_confidence.json
```

只输出高置信度的结果。

## 命令行参数详解

### 目标参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `-t, --target` | 单个目标 | `-t 192.168.1.0/24` |
| `-f, --file` | 目标文件 | `-f targets.txt` |

### 性能参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-w, --workers` | 20 | 并发线程数 |
| `--timeout` | 5 | 请求超时(秒) |
| `--retry` | 2 | 重试次数 |
| `--rate-limit` | 0 | 请求间隔(秒) |
| `--ports` | - | 自定义端口列表 |

### 输出参数

| 参数 | 说明 |
|------|------|
| `-o, --output` | 保存JSON结果 |
| `-v, --verbose` | 详细输出 |
| `--realtime` | 实时输出发现的目标 |
| `--no-progress` | 禁用进度条 |
| `--stats` | 显示统计信息 |

### 过滤参数

| 参数 | 说明 |
|------|------|
| `--min-confidence` | 最小置信度 (LOW/MEDIUM/HIGH) |
| `--config` | 指定配置文件 |

## 目标格式

支持以下格式：

```
# IP地址
192.168.1.100

# IP:PORT
192.168.1.100:8080

# CIDR网段
192.168.1.0/24
10.0.0.0/16

# 域名
example.com
api.example.com

# 完整URL
http://example.com:8080
https://api.example.com
```

## 输出说明

### 置信度级别

- **HIGH** (红色): 分数 >= 80，强烈匹配
- **MEDIUM** (黄色): 分数 >= 40，可能匹配
- **LOW** (绿色): 分数 < 40，弱匹配

### 实时输出示例

```
扫描进度 |████████| 500/2032 [00:30<01:45, 14.5url/s] 发现:3
[发现] http://192.168.1.100:8080 [置信度: HIGH | 分数: 125]
[发现] http://192.168.1.105:3000 [置信度: MEDIUM | 分数: 65]
```

### 详细输出 (-v)

```bash
python scanner.py -t 192.168.1.100 -v
```

输出:
```
[+] http://192.168.1.100:8080 [置信度: HIGH | 分数: 125]
    - Header: X-OpenClaw-Version=1.2.3
    - Keyword 'openclaw' at /
    - JSON key 'agents' at /api/v1/agents
    - Agent API accessible (GET)
```

## 性能优化建议

### 快速扫描
```bash
python scanner.py -t 192.168.1.0/24 -w 100 --timeout 3 --retry 1
```

### 平衡模式
```bash
python scanner.py -t 192.168.1.0/24 -w 20 --timeout 5 --retry 2
```

### 隐蔽模式
```bash
python scanner.py -t 192.168.1.0/24 -w 5 --timeout 10 --rate-limit 2
```

## 自定义配置

### 修改默认端口

编辑 `fingerprints.json`:
```json
{
  "scanner_config": {
    "default_ports": [80, 443, 8080, 8443, 3000, 5000]
  }
}
```

### 添加自定义特征

```json
{
  "endpoints": {
    "/my/custom/api": ["GET"]
  },
  "keywords": [
    "my-framework"
  ],
  "weights": {
    "Keyword 'my-framework'": 50
  }
}
```

### 使用自定义配置

```bash
python scanner.py -t 192.168.1.100 --config my_config.json
```

## 常见问题

### Q: 如何扫描多个C段？

A: 创建目标文件，每行一个CIDR:
```bash
echo "192.168.1.0/24" > targets.txt
echo "192.168.2.0/24" >> targets.txt
python scanner.py -f targets.txt --realtime
```

### Q: 如何只扫描特定端口？

A: 使用 `--ports` 参数:
```bash
python scanner.py -t 192.168.1.0/24 --ports 80,443,8080
```

### Q: 扫描速度太慢怎么办？

A: 增加并发数，减少超时:
```bash
python scanner.py -t 192.168.1.0/24 -w 100 --timeout 3
```

### Q: 如何避免被检测？

A: 降低并发，增加间隔:
```bash
python scanner.py -t 192.168.1.0/24 -w 5 --rate-limit 2
```

### Q: 如何保存扫描结果？

A: 使用 `-o` 参数:
```bash
python scanner.py -f targets.txt -o results.json
```

## 完整示例

### 示例1: 企业内网扫描

```bash
# 扫描多个内网段，实时输出，保存结果
python scanner.py -f internal_networks.txt \
  --realtime \
  -w 50 \
  --min-confidence MEDIUM \
  -o scan_results.json \
  --stats
```

### 示例2: 外网目标扫描

```bash
# 谨慎扫描外网目标
python scanner.py -f external_targets.txt \
  -w 10 \
  --rate-limit 1 \
  --timeout 10 \
  --retry 3 \
  -o external_results.json
```

### 示例3: 快速验证

```bash
# 快速验证单个目标
python scanner.py -t 192.168.1.100:8080 -v
```

## 注意事项

⚠️ **重要提示**:
1. 仅在授权范围内使用
2. 遵守目标系统的访问策略
3. 控制扫描速率避免影响服务
4. 注意法律法规要求
5. 建议先小范围测试再大规模扫描

## 获取帮助

```bash
# 查看所有参数
python scanner.py --help

# 查看版本信息
python scanner.py --version
```

## 相关文档

- `README.md` - 完整使用说明
- `DETECTION_GUIDE.md` - 检测技术文档
- `fingerprints.json` - 指纹配置文件
- `targets.txt.example` - 目标文件示例
