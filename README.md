# TeleSnare - Advanced Telegram Extractor

TeleSnare 是一个用于 Burp Suite 的高级 Telegram 提取器扩展，专为授权的渗透测试和安全评估设计。该插件利用 Jython 编写，自动化从 HTTP 流量中提取 Telegram 的 token 和 chat_id，并以丰富的 UI 展示所有结果，同时支持 CSV 导出，便于后续数据分析。

## 特性

- **多种解析方式**
  - **JSON 解析**：若响应为 JSON 格式，则递归遍历所有嵌套结构，提取关键信息。
  - **直接正则匹配**：对原始文本应用预编译正则表达式，快速匹配标准格式。
  - **HTML/XML 预处理**：对 HTML 标签和 XML 结构进行预处理后匹配，确保覆盖混合格式数据。
  - **自定义规则支持**：预留接口，允许用户添加自定义匹配规则，扩展特殊格式的处理。

- **高精度匹配**
  - 内置优化后的正则表达式，能够匹配标准的 Telegram token 和 chat_id 格式，并可处理引号、空格、大小写等多种情况。

- **友好的用户界面**
  - 自定义 Burp Suite 标签页展示日志和结果表格。
  - 结果表格支持点击列标题进行排序操作，方便数据浏览。
  - 提供 CSV 导出功能，将结果导出到文件，便于进一步分析。

- **详细的调试日志**
  - 内置详细的 debug 输出，帮助开发者定位问题和扩展解析策略。

- **真实 HTTP 来源展示**
  - 自动提取 HTTP 请求中的 URL 信息，并在结果中显示来源 URI，便于追溯数据来源。

## 安装与配置

### 环境要求

- **Burp Suite**：需要使用合法授权版本的 Burp Suite。
- **Jython Standalone**：下载 [jython-standalone-2.7.x.jar](https://repo1.maven.org/maven2/org/python/jython-standalone/)（推荐版本 2.7.2 或 2.7.3）。
- **操作系统要求**：建议将插件放在仅含 ASCII 字符的路径下，以避免编码问题。

### 安装步骤

1. 下载本项目的 `TeleSnare.py` 文件和合适版本的 Jython Standalone JAR 文件。
2. 打开 Burp Suite，进入 **Extender → Extensions**。
3. 点击 **Add** 按钮，选择扩展类型为 **Python**，然后选择 `TeleSnare.py` 文件，并在扩展加载对话框中指定 Jython Standalone JAR 文件的路径。
4. 确认加载成功后，在 Burp Suite 的右侧选项卡中会出现 “TeleSnare” 标签页，显示日志和结果。

## 使用说明

- **实时提取**：插件会自动监听经过 Burp 的 HTTP 流量，匹配并提取 Telegram 的 token 与 chat_id，并在 UI 中实时显示。
- **日志记录**：所有匹配到的凭证都会记录到当前目录下的 `telegram_extraction_results.log` 文件中，采用 UTF-8 编码保存。
- **CSV 导出**：点击 UI 工具栏的 “Export CSV” 按钮，将当前结果导出为 `TeleSnare_results.csv` 文件，方便后续分析。
- **结果排序**：在结果表格中，点击任意列标题即可对该列数据进行排序。

## 开发与扩展

- **多模块设计**：项目代码分为配置管理、数据持久化、业务逻辑与 UI 展示模块，便于后续维护和扩展。
- **自定义匹配规则**：在 `BusinessLogic` 类中预留了扩展接口，用户可根据需要添加额外的解析规则，处理其他格式的数据（如 URL 参数、Cookie 等）。
- **调试信息**：详细的 debug 输出记录每个解析环节的匹配情况，便于开发者调试和完善匹配策略。

## 免责声明

本插件仅供授权渗透测试和安全评估使用，未经许可的使用可能违反相关法律法规。作者对使用本工具造成的任何后果不承担任何责任。

## 许可证

本项目采用 [MIT 许可证](LICENSE).