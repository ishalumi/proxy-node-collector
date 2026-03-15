# Proxy Node Collector

自动聚合互联网公开免费代理节点，定时爬取 + 去重，输出标准订阅格式。

## 订阅链接

| 格式 | 链接 |
|------|------|
| 纯文本 (一行一个 URI) | `https://raw.githubusercontent.com/ishalumi/proxy-node-collector/main/output/nodes.txt` |
| Base64 (标准订阅) | `https://raw.githubusercontent.com/ishalumi/proxy-node-collector/main/output/nodes_base64.txt` |

### 在 easy_proxies 中使用

```yaml
subscriptions:
  - "https://raw.githubusercontent.com/ishalumi/proxy-node-collector/main/output/nodes_base64.txt"
```

或下载 `output/nodes.txt` 作为 `nodes_file` 使用。

## 数据源

见 [`sources.yaml`](sources.yaml)，当前聚合 20 个公开源（15 个仓库/站点）：

- **chengaopan/AutoMergePublicNodes** - 大型 base64 聚合源
- **barry-far/V2ray-Config** - 全协议聚合（每 15 分钟更新）
- **MatinGhanbari/v2ray-configs** - 超大节点池（7500+ 节点）
- **mahdibland/V2RayAggregator** - Eternity 过滤聚合（每 12 小时）
- **Epodonios/v2ray-configs** - 自动更新节点池（7000+ 节点）
- **xyfqzy/free-nodes** - 多源采集聚合
- **Barabama/FreeNodes** - 多子源爬虫 (nodefree, v2rayshare, wenode 等)
- **peasoft/NoMoreWalls** - 高频抓取合并（每日多次）
- **mfuu/v2ray** - V2Ray 订阅（每 8 小时更新）
- **ermaozi/get_subscribe** - 自动订阅采集（每 12 小时）
- **yzcjd/jiedian** - Telegram 频道节点聚合
- **snakem982/proxypool** - Clash Meta 聚合池
- **free-nodes/clashfree** - 每日快照源
- **mianfeiclash.com** - 非 GitHub 网站日更源
- **Pawdroid/Free-servers** - 固定订阅备用源

## 更新频率

GitHub Actions **每 6 小时**自动运行，也支持手动触发。

## 添加新源

编辑 `sources.yaml`：

```yaml
# 普通源
- name: "新源"
  url: "https://example.com/nodes.txt"

# 动态日期 URL
- name: "日期源"
  url_template: "https://example.com/nodes_{date}.txt"
  date_format: "%Y%m%d"
```

脚本自动识别 base64 / 纯文本格式，无需手动指定。

## 本地运行

```bash
pip install pyyaml
python fetch.py
```

## 免责声明

- 本项目**仅爬取互联网公开资源**并进行聚合整理，不提供、不运营任何代理服务。
- 项目**不对节点的可用性、安全性、速度、合法性作任何担保**。
- 使用者因使用本项目所产生的一切后果，由使用者自行承担，与本项目及作者无关。
- 请遵守您所在地区的法律法规，本项目仅供学习与技术研究用途。
