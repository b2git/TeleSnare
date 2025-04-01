# TeleSnare - Telegram Extractor

Burp Suite 扩展，用于自动从 HTTP 流量中提取 Telegram 的 token 和 chat_id。只在授权的渗透测试中使用，别瞎搞

## 特点

- 自动捕获 HTTP 流量中的 Telegram token 和 chat_id
- 多种解析方式：JSON、HTML、XML、纯文本混合解析
- 结果直接显示在 Burp 自定义标签页中，支持排序和 CSV 导出

## 使用

1. 下载 `TeleSnare.py` 和合适版本的 `jython-standalone`。
2. 在 Burp Suite 的 **Extender** 模块中添加 Python 扩展，并指定 Jython 路径。
3. 开启代理，流量经过时自动提取，结果显示在 “TeleSnare” 标签页。

## 注意

仅用于授权渗透测试，请勿用于非法用途！
