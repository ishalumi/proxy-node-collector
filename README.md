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

见 [`sources.yaml`](sources.yaml)，当前聚合 11 个公开源：

- **NoMoreWalls** (AutoMergePublicNodes) - 最大聚合源
- **free18/v2ray** - 大量节点
- **shaoyouvip/free** - 公益节点
- **Barabama/FreeNodes** - 多子源爬虫 (nodefree, v2rayshare, wenode 等)
- **free-nodes/v2rayfree** - 每日更新
- **a2470982985/getNode** - 每小时更新

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

所有节点均来自互联网公开资源，仅供学习交流使用，请遵守当地法律法规。
