# OpenClaw 指纹扫描器使用指南

[English](README.md) | [简体中文](README_CN.md)

## 安装

```bash
pip install -r requirements.txt
```

## 基本使用

### 扫描单个目标

```bash
# 扫描IP地址（自动扫描所有默认端口）
python scanner.py -t 192.168.1.100

# 扫描指定端口
python scanner.py -t 192.168.1.100:8080

# 扫描域名
python scanner.py -t example.com
```

### 批量扫描

```bash
# 从文件读取目标列表
python scanner.py -f targets.txt

# 保存结果到JSON文件
python scanner.py -f targets.txt -o results.json
```

## 配置文件

扫描器使用 `fingerprints.json` 配置所有检测特征和参数。

### 使用自定义配置

```bash
# 指定配置文件
python scanner.py -t 192.168.1.100 --config my_config.json
```

### 配置文件结构

```json
{
  "endpoints": {},           // API端点列表
  "headers": [],            // 响应头特征
  "keywords": [],           // 关键字列表
  "json_keys": [],          // JSON结构特征
  "error_patterns": [],     // 错误消息模式
  "websocket_endpoints": [], // WebSocket端点
  "weights": {},            // 特征权重
  "confidence_thresholds": {}, // 置信度阈值
  "scanner_config": {},     // 扫描器参数
  "output_colors": {}       // 输出颜色
}
```

### 自定义特征

编辑 `fingerprints.json` 添加新特征：

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

## 高级选项

### 性能调优

```bash
# 设置并发线程数（默认20）
python scanner.py -f targets.txt -w 50

# 设置请求超时（默认5秒）
python scanner.py -f targets.txt --timeout 10

# 设置重试次数（默认2次）
python scanner.py -f targets.txt --retry 3

# 设置请求间隔（避免触发防护）
python scanner.py -f targets.txt --rate-limit 0.5
```

### 自定义端口

```bash
# 指定要扫描的端口列表
python scanner.py -t 192.168.1.100 --ports 80,443,8080,8443,3000
```

### 结果过滤

```bash
# 只显示高置信度结果
python scanner.py -f targets.txt --min-confidence HIGH

# 只显示中等及以上置信度
python scanner.py -f targets.txt --min-confidence MEDIUM
```

### 输出控制

```bash
# 详细输出（显示所有指纹）
python scanner.py -t 192.168.1.100 -v

# 禁用进度条
python scanner.py -f targets.txt --no-progress

# 显示统计信息
python scanner.py -f targets.txt --stats
```

## 目标文件格式

targets.txt 示例：

```
# 这是注释行
192.168.1.100
192.168.1.101:8080
10.0.0.50
http://example.com:3000
https://api.example.com
```

## 完整示例

```bash
# 高性能扫描：50线程，10秒超时，只显示高置信度结果
python scanner.py -f targets.txt -w 50 --timeout 10 --min-confidence HIGH -o results.json --stats

# 谨慎扫描：低并发，有间隔，详细输出
python scanner.py -f targets.txt -w 5 --rate-limit 1 -v --stats
```

## 输出说明

### 置信度级别

- **HIGH** (红色): 分数 >= 80，强烈匹配OpenClaw特征
- **MEDIUM** (黄色): 分数 >= 40，可能是OpenClaw实例
- **LOW** (绿色): 分数 < 40，弱匹配

### 输出示例

```
[+] http://192.168.1.100:8080 [置信度: HIGH | 分数: 125]
    - Header: X-OpenClaw-Version=1.2.3
    - Keyword 'openclaw' at /
    - JSON key 'agents' at /api/v1/agents
    - Agent API accessible (GET)
```

## 性能建议

### 快速扫描
- 高并发 (-w 50+)
- 短超时 (--timeout 3)
- 无速率限制

### 隐蔽扫描
- 低并发 (-w 5-10)
- 长超时 (--timeout 10)
- 添加间隔 (--rate-limit 1-2)

### 大规模扫描
- 中等并发 (-w 20-30)
- 适中超时 (--timeout 5)
- 分批扫描
- 使用 --min-confidence 过滤

## 注意事项

⚠️ **重要提示**：
1. 仅在授权范围内使用
2. 遵守目标系统的访问策略
3. 控制扫描速率避免影响目标服务
4. 不要扫描未授权的系统
5. 注意法律法规要求

## 故障排除

### 依赖安装失败
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### 连接超时过多
- 增加超时时间: --timeout 10
- 减少并发数: -w 10
- 检查网络连接

### 误报过多
- 提高置信度过滤: --min-confidence MEDIUM
- 检查目标列表是否正确
- 调整配置文件中的权重和阈值

### 扫描速度慢
- 增加并发数: -w 50
- 减少超时时间: --timeout 3
- 减少重试次数: --retry 1

### 自定义检测规则
- 编辑 fingerprints.json 添加新端点
- 调整特征权重优化检测准确率
- 修改置信度阈值适应不同场景

## 文件说明

- **scanner.py** - 主扫描程序
- **fingerprints.json** - 指纹配置文件（可自定义）
- **requirements.txt** - Python依赖
- **README.md** - 使用说明
- **DETECTION_GUIDE.md** - 检测技术文档
