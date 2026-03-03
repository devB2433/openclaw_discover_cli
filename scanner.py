#!/usr/bin/env python3
import requests
import argparse
import json
import re
import ipaddress
import time
import logging
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from collections import defaultdict
from tqdm import tqdm
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')
requests.packages.urllib3.disable_warnings()

def load_fingerprints(config_file='fingerprints.json'):
    """加载指纹配置文件"""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(script_dir, config_file)

    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"配置文件未找到: {config_path}")
        exit(1)
    except json.JSONDecodeError as e:
        logging.error(f"配置文件格式错误: {e}")
        exit(1)

class OpenClawScanner:
    def __init__(self, timeout=5, ports=None, max_workers=20, retry=2, rate_limit=0, config_file='fingerprints.json'):
        self.timeout = timeout
        self.max_workers = max_workers
        self.retry = retry
        self.rate_limit = rate_limit
        self.stats = defaultdict(int)

        # 加载指纹配置
        self.config = load_fingerprints(config_file)

        # 从配置加载默认端口
        self.ports = ports or self.config['scanner_config']['default_ports']

        # 配置会话和重试策略
        self.session = requests.Session()
        retry_strategy = Retry(
            total=retry,
            backoff_factor=self.config['scanner_config']['retry_backoff_factor'],
            status_forcelist=self.config['scanner_config']['retry_status_forcelist'],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.config['scanner_config']['pool_connections'],
            pool_maxsize=self.config['scanner_config']['pool_maxsize']
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        self.session.headers.update({'User-Agent': self.config['scanner_config']['user_agent']})

        # 配置日志
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%H:%M:%S'
        )

    def normalize_target(self, target):
        """规范化目标为URL列表（支持IP、IP:PORT、域名、CIDR）"""
        urls = []

        # 如果已经是完整URL
        if target.startswith('http://') or target.startswith('https://'):
            return [target]

        # 检查是否是CIDR格式
        if '/' in target:
            try:
                network = ipaddress.ip_network(target, strict=False)
                # CIDR网段，返回IP列表而不是URL（延迟生成URL）
                return [str(ip) for ip in network.hosts()]
            except:
                pass

        # 检查是否包含端口
        if ':' in target and not target.count(':') > 1:  # 排除IPv6
            host, port = target.rsplit(':', 1)
            urls.append(f'http://{host}:{port}')
            urls.append(f'https://{host}:{port}')
        else:
            # 尝试解析为IP地址
            try:
                ipaddress.ip_address(target)
                # 是IP地址，返回IP而不是URL（延迟生成）
                return [target]
            except:
                # 可能是域名
                urls.append(f'http://{target}')
                urls.append(f'https://{target}')

        return urls

    def ip_to_urls(self, ip):
        """将IP地址转换为URL列表"""
        urls = []
        for port in self.ports:
            urls.append(f'http://{ip}:{port}')
            if port in [443, 8443]:
                urls.append(f'https://{ip}:{port}')
        return urls

    def calculate_confidence(self, fingerprints):
        """计算置信度分数"""
        score = 0
        weights = self.config['weights']
        default_weight = weights.get('default', 5)

        for fp in fingerprints:
            matched = False
            for pattern, weight in weights.items():
                if pattern != 'default' and pattern in fp:
                    score += weight
                    matched = True
                    break
            if not matched:
                score += default_weight

        thresholds = self.config['confidence_thresholds']
        if score >= thresholds['HIGH']:
            return 'HIGH', score
        elif score >= thresholds['MEDIUM']:
            return 'MEDIUM', score
        else:
            return 'LOW', score

    def check_target(self, url):
        """检测目标是否为OpenClaw实例"""
        fingerprints = []

        try:
            self.stats['total_checked'] += 1

            # 速率限制
            if self.rate_limit > 0:
                time.sleep(self.rate_limit)

            # 从配置加载端点
            endpoints = self.config['endpoints']

            for endpoint, methods in endpoints.items():
                for method in methods:
                    full_url = urljoin(url, endpoint)
                    try:
                        if method == 'GET':
                            resp = self.session.get(full_url, timeout=self.timeout, verify=False, allow_redirects=False)
                        else:
                            resp = self.session.post(full_url, json={}, timeout=self.timeout, verify=False, allow_redirects=False)

                        self.stats['requests_sent'] += 1

                        # 响应头指纹（从配置加载）
                        for header in self.config['headers']:
                            if header in resp.headers:
                                value = resp.headers[header]
                                # 使用配置的关键字匹配
                                match_keywords = self.config['scanner_config']['header_match_keywords']
                                if any(kw in value.lower() for kw in match_keywords):
                                    fingerprints.append(f"Header: {header}={value}")

                        # 响应体关键字（从配置加载）
                        text_lower = resp.text.lower()
                        for kw in self.config['keywords']:
                            if kw in text_lower:
                                fingerprints.append(f"Keyword '{kw}' at {endpoint}")
                                break

                        # JSON结构特征（从配置加载）
                        if 'application/json' in resp.headers.get('Content-Type', ''):
                            try:
                                data = resp.json()
                                for key in self.config['json_keys']:
                                    if key in data:
                                        fingerprints.append(f"JSON key '{key}' at {endpoint}")
                            except:
                                pass

                        # 状态码模式
                        if endpoint == '/api/v1/agents' and resp.status_code == 200:
                            fingerprints.append(f"Agent API accessible ({method})")

                        if endpoint in ['/api/docs', '/api/swagger'] and resp.status_code == 200:
                            fingerprints.append(f"API documentation exposed at {endpoint}")

                        # 错误消息特征（从配置加载）
                        for pattern in self.config['error_patterns']:
                            if re.search(pattern, text_lower):
                                fingerprints.append(f"Error pattern '{pattern}' at {endpoint}")

                    except requests.exceptions.Timeout:
                        self.stats['timeouts'] += 1
                    except requests.exceptions.ConnectionError:
                        self.stats['connection_errors'] += 1
                    except Exception as e:
                        self.stats['other_errors'] += 1
                        logging.debug(f"Error checking {full_url}: {e}")

            # WebSocket检测（从配置加载）
            for ws_endpoint in self.config['websocket_endpoints']:
                full_url = urljoin(url, ws_endpoint)
                try:
                    resp = self.session.get(full_url, timeout=self.timeout, verify=False, allow_redirects=False)
                    ws_codes = self.config['scanner_config']['websocket_status_codes']
                    if resp.status_code in ws_codes or 'upgrade' in resp.headers.get('Connection', '').lower():
                        fingerprints.append(f"WebSocket endpoint at {ws_endpoint}")
                except:
                    pass

            # 去重
            fingerprints = list(set(fingerprints))

            if fingerprints:
                self.stats['targets_found'] += 1
                return fingerprints
            return None

        except Exception as e:
            logging.error(f"Critical error checking {url}: {e}")
            self.stats['critical_errors'] += 1
            return None

    def scan(self, targets, show_progress=True, realtime_output=False):
        """扫描多个目标"""
        results = []
        all_targets = []

        # 第一步：展开目标（可能包含CIDR）
        for target in targets:
            normalized = self.normalize_target(target)
            all_targets.extend(normalized)

        # 去重
        all_targets = list(set(all_targets))

        # 第二步：为IP生成URL，为其他直接使用
        all_urls = []
        for target in all_targets:
            # 检查是否是纯IP
            try:
                ipaddress.ip_address(target)
                all_urls.extend(self.ip_to_urls(target))
            except:
                # 已经是URL
                all_urls.append(target)

        all_urls = list(set(all_urls))

        logging.info(f"目标数: {len(targets)} | IP/域名数: {len(all_targets)} | URL数: {len(all_urls)}")

        start_time = time.time()
        found_count = 0

        # 使用进度条
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = {executor.submit(self.check_target, url): url for url in all_urls}

            if show_progress:
                pbar = tqdm(
                    total=len(all_urls),
                    desc="扫描进度",
                    unit="url",
                    bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}] 发现:{postfix}'
                )
                pbar.set_postfix_str(f"{found_count}")

                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        fps = future.result()
                        if fps:
                            confidence, score = self.calculate_confidence(fps)
                            result = {
                                'target': url,
                                'fingerprints': fps,
                                'confidence': confidence,
                                'score': score
                            }
                            results.append(result)
                            found_count += 1
                            pbar.set_postfix_str(f"{found_count}")

                            # 实时输出
                            if realtime_output:
                                colors = self.config['output_colors']
                                color = colors.get(confidence, '')
                                reset = colors['RESET']
                                tqdm.write(f"{color}[发现] {url} [置信度: {confidence} | 分数: {score}]{reset}")
                    except Exception as e:
                        logging.debug(f"处理 {url} 时出错: {e}")
                    pbar.update(1)

                pbar.close()
            else:
                for future in as_completed(futures):
                    url = futures[future]
                    try:
                        fps = future.result()
                        if fps:
                            confidence, score = self.calculate_confidence(fps)
                            results.append({
                                'target': url,
                                'fingerprints': fps,
                                'confidence': confidence,
                                'score': score
                            })
                    except Exception as e:
                        logging.debug(f"处理 {url} 时出错: {e}")

        # 按置信度排序
        results.sort(key=lambda x: x['score'], reverse=True)
        return results

    def print_stats(self):
        """打印统计信息"""
        print("\n" + "="*60)
        print("扫描统计")
        print("="*60)
        print(f"检查的URL数量: {self.stats['total_checked']}")
        print(f"发送的请求数: {self.stats['requests_sent']}")
        print(f"发现的目标数: {self.stats['targets_found']}")
        print(f"超时次数: {self.stats['timeouts']}")
        print(f"连接错误: {self.stats['connection_errors']}")
        print(f"其他错误: {self.stats['other_errors']}")
        print(f"严重错误: {self.stats['critical_errors']}")
        print("="*60)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OpenClaw指纹扫描器 v2.0')
    parser.add_argument('-t', '--target', help='单个目标URL/IP/CIDR (如: 192.168.1.0/24)')
    parser.add_argument('-f', '--file', help='目标列表文件')
    parser.add_argument('-o', '--output', help='输出JSON结果到文件')
    parser.add_argument('-v', '--verbose', action='store_true', help='详细输出')
    parser.add_argument('-w', '--workers', type=int, default=20, help='并发线程数 (默认: 20)')
    parser.add_argument('--timeout', type=int, default=5, help='请求超时时间(秒) (默认: 5)')
    parser.add_argument('--retry', type=int, default=2, help='重试次数 (默认: 2)')
    parser.add_argument('--rate-limit', type=float, default=0, help='请求间隔(秒) (默认: 0)')
    parser.add_argument('--ports', help='自定义端口列表，逗号分隔 (如: 80,443,8080)')
    parser.add_argument('--min-confidence', choices=['LOW', 'MEDIUM', 'HIGH'], default='LOW',
                        help='最小置信度过滤 (默认: LOW)')
    parser.add_argument('--no-progress', action='store_true', help='禁用进度条')
    parser.add_argument('--realtime', action='store_true', help='实时输出发现的目标')
    parser.add_argument('--stats', action='store_true', help='显示统计信息')
    parser.add_argument('--config', default='fingerprints.json', help='指纹配置文件 (默认: fingerprints.json)')
    args = parser.parse_args()

    # 配置日志级别
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # 解析自定义端口
    ports = None
    if args.ports:
        ports = [int(p.strip()) for p in args.ports.split(',')]

    scanner = OpenClawScanner(
        timeout=args.timeout,
        ports=ports,
        max_workers=args.workers,
        retry=args.retry,
        rate_limit=args.rate_limit,
        config_file=args.config
    )

    targets = []
    if args.target:
        targets.append(args.target)
    elif args.file:
        try:
            with open(args.file) as f:
                targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception as e:
            logging.error(f"读取目标文件失败: {e}")
            exit(1)
    else:
        parser.print_help()
        exit(1)

    logging.info(f"开始扫描 {len(targets)} 个目标...")
    start_time = time.time()

    results = scanner.scan(targets, show_progress=not args.no_progress, realtime_output=args.realtime)

    # 过滤置信度
    confidence_levels = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2}
    min_level = confidence_levels[args.min_confidence]
    filtered_results = [r for r in results if confidence_levels[r['confidence']] >= min_level]

    elapsed = time.time() - start_time
    logging.info(f"扫描完成，耗时 {elapsed:.2f} 秒")
    logging.info(f"发现 {len(filtered_results)} 个OpenClaw实例 (置信度 >= {args.min_confidence})\n")

    # 输出结果（如果没有实时输出）
    if not args.realtime:
        for r in filtered_results:
            colors = scanner.config['output_colors']
            color = colors.get(r['confidence'], '')
            reset = colors['RESET']
            print(f"{color}[+] {r['target']} [置信度: {r['confidence']} | 分数: {r['score']}]{reset}")
            if args.verbose:
                for fp in r['fingerprints']:
                    print(f"    - {fp}")
    elif args.verbose:
        # 实时模式下，如果需要详细信息，再次输出
        print("\n" + "="*60)
        print("详细结果")
        print("="*60)
        for r in filtered_results:
            colors = scanner.config['output_colors']
            color = colors.get(r['confidence'], '')
            reset = colors['RESET']
            print(f"{color}[+] {r['target']} [置信度: {r['confidence']} | 分数: {r['score']}]{reset}")
            for fp in r['fingerprints']:
                print(f"    - {fp}")

    # 保存结果
    if args.output:
        try:
            with open(args.output, 'w', encoding='utf-8') as f:
                json.dump(filtered_results, f, indent=2, ensure_ascii=False)
            logging.info(f"结果已保存到 {args.output}")
        except Exception as e:
            logging.error(f"保存结果失败: {e}")

    # 显示统计
    if args.stats:
        scanner.print_stats()
