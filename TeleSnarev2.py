# -*- coding: utf-8 -*-
import re
import os
import datetime
import json
import csv
import javax.swing as swing
import java.awt.BorderLayout as BorderLayout
import java.awt.FlowLayout as FlowLayout
from javax.swing.table import DefaultTableModel
from burp import IBurpExtender, IHttpListener, ITab

# 定义全局常量，确保为 Unicode 字符串
HTTP_PLACEHOLDER = u"未知URI"

def debug(msg):
    try:
        print(u"[TeleSnare DEBUG] " + msg)
    except Exception as e:
        pass

##############################
# ConfigManager：管理日志路径及正则表达式配置
##############################
class ConfigManager:
    def __init__(self):
        try:
            self.log_file = os.path.join(os.getcwd(), "telegram_extraction_results.log")
            # Token 正则保持不变
            self.token_regex_pattern = r"\b\d{9,10}:[A-Za-z0-9_-]{35,45}\b"
            # 更新后的 chatID 正则表达式，支持各种引号、空格及大小写，并使用单词边界
            self.chatid_regex_pattern = r'\b(?:chat(?:[_-]?id)|chatid)\b\s*[:=]\s*["\']?([-]?\d+)["\']?'
            debug("ConfigManager 初始化成功。日志文件路径: " + self.log_file)
        except Exception as e:
            debug("ConfigManager 初始化异常: " + str(e))
    
    def get_log_file(self):
        return self.log_file
    
    def get_token_regex(self):
        try:
            return re.compile(self.token_regex_pattern)
        except Exception as e:
            debug("编译 token 正则表达式异常: " + str(e))
            return None
    
    def get_chatid_regex(self):
        try:
            return re.compile(self.chatid_regex_pattern, re.IGNORECASE)
        except Exception as e:
            debug("编译 chatid 正则表达式异常: " + str(e))
            return None

##############################
# ResultManager：将扫描结果写入日志文件（以UTF-8保存）
##############################
class ResultManager:
    def __init__(self, config):
        try:
            self.log_file = config.get_log_file()
            if not os.path.exists(self.log_file):
                with open(self.log_file, "w") as f:
                    f.write(u"Telegram Credentials Extraction Log\n".encode("utf-8"))
            debug("ResultManager 初始化成功。")
        except Exception as e:
            debug("ResultManager 初始化异常: " + str(e))
    
    def add_result(self, token, chatid, http_info):
        try:
            timestamp = datetime.datetime.now().isoformat()
            result = {u"timestamp": timestamp, u"token": token, u"chatid": chatid, u"http_info": http_info}
            with open(self.log_file, "a") as f:
                f.write((str(result) + "\n").encode("utf-8"))
            debug("保存结果成功: " + str(result))
            return timestamp
        except Exception as e:
            debug("保存结果异常: " + str(e))
            return None

##############################
# BusinessLogic：解析 HTTP 响应，通过多种解析方式提取凭证
##############################
class BusinessLogic:
    def __init__(self, config):
        try:
            self.token_regex = config.get_token_regex()
            self.chatid_regex = config.get_chatid_regex()
            # 可扩展：用户可在此添加自定义匹配规则，格式为 (name, token_pattern, chatid_pattern)
            self.custom_patterns = []  # 例如： self.custom_patterns.append(("URL_PARAM", re.compile(...), re.compile(...)))
            debug("BusinessLogic 初始化成功。")
        except Exception as e:
            debug("BusinessLogic 初始化异常: " + str(e))
    
    def extract_credentials(self, response_str):
        tokens, chatids = [], []
        # 1. JSON 解析（如果响应看起来像JSON）
        if response_str.lstrip().startswith("{") or response_str.lstrip().startswith("["):
            try:
                data = json.loads(response_str)
                jt, jc = self.recursive_search(data)
                tokens.extend(jt)
                chatids.extend(jc)
                debug("JSON解析成功，匹配到 tokens: " + str(jt) + ", chatids: " + str(jc))
            except Exception as e:
                debug("JSON解析失败，继续其他解析方式: " + str(e))
        else:
            debug("响应非JSON格式，跳过JSON解析。")
        
        # 2. 直接对原始文本应用正则匹配
        try:
            rt = self.token_regex.findall(response_str) if self.token_regex else []
            rc = self.chatid_regex.findall(response_str) if self.chatid_regex else []
            debug("原始文本正则匹配到 tokens: " + str(rt) + ", chatids: " + str(rc))
            tokens.extend(rt)
            chatids.extend(rc)
        except Exception as e:
            debug("直接正则匹配异常: " + str(e))
        
        # 3. HTML预处理：如果检测到 <html 标签，则剔除标签后再匹配
        if "<html" in response_str.lower():
            try:
                clean_html = re.sub("<[^>]+>", " ", response_str)
                rt_html = self.token_regex.findall(clean_html) if self.token_regex else []
                rc_html = self.chatid_regex.findall(clean_html) if self.chatid_regex else []
                debug("HTML预处理匹配到 tokens: " + str(rt_html) + ", chatids: " + str(rc_html))
                tokens.extend(rt_html)
                chatids.extend(rc_html)
            except Exception as e:
                debug("HTML预处理异常: " + str(e))
        
        # 4. XML预处理：如果响应看起来像XML，则解析并提取文本
        if response_str.lstrip().startswith("<?xml") or "<root" in response_str.lower():
            try:
                import xml.etree.ElementTree as ET
                root = ET.fromstring(response_str)
                xml_text = " ".join(root.itertext())
                rt_xml = self.token_regex.findall(xml_text) if self.token_regex else []
                rc_xml = self.chatid_regex.findall(xml_text) if self.chatid_regex else []
                debug("XML预处理匹配到 tokens: " + str(rt_xml) + ", chatids: " + str(rc_xml))
                tokens.extend(rt_xml)
                chatids.extend(rc_xml)
            except Exception as e:
                debug("XML预处理异常: " + str(e))
        
        # 5. 自定义匹配规则（如果用户添加了）
        if self.custom_patterns:
            for name, pattern_token, pattern_chat in self.custom_patterns:
                try:
                    rt_custom = pattern_token.findall(response_str)
                    rc_custom = pattern_chat.findall(response_str)
                    debug("自定义规则[" + name + "]匹配到 tokens: " + str(rt_custom) + ", chatids: " + str(rc_custom))
                    tokens.extend(rt_custom)
                    chatids.extend(rc_custom)
                except Exception as e:
                    debug("自定义规则[" + name + "]异常: " + str(e))
        
        # 6. 去除重复项
        tokens = list(set(tokens))
        chatids = list(set(chatids))
        return tokens, chatids
    
    def recursive_search(self, data):
        tokens, chatids = [], []
        try:
            if isinstance(data, dict):
                for key, value in data.items():
                    if isinstance(value, basestring):
                        key_lower = key.lower()
                        if key_lower in ["token", "bot_token"]:
                            found = self.token_regex.findall(value) if self.token_regex else []
                            tokens.extend(found)
                        elif key_lower in ["chat_id", "chatid", "chatidnum"]:
                            found = self.chatid_regex.findall(value) if self.chatid_regex else []
                            chatids.extend(found)
                    else:
                        t, c = self.recursive_search(value)
                        tokens.extend(t)
                        chatids.extend(c)
            elif isinstance(data, list):
                for item in data:
                    t, c = self.recursive_search(item)
                    tokens.extend(t)
                    chatids.extend(c)
        except Exception as e:
            debug("递归搜索异常: " + str(e))
        return tokens, chatids

##############################
# UIManager：提供带工具栏、日志、结果表格、导出CSV及列排序功能的界面
##############################
class UIManager:
    def __init__(self):
        try:
            self.panel = swing.JPanel(BorderLayout())
            self.toolbar = swing.JPanel(FlowLayout(FlowLayout.LEFT))
            self.clearButton = swing.JButton("Clear")
            self.refreshButton = swing.JButton("Refresh")
            self.exportButton = swing.JButton("Export CSV")
            self.statusLabel = swing.JLabel("Status: Ready")
            self.toolbar.add(self.clearButton)
            self.toolbar.add(self.refreshButton)
            self.toolbar.add(self.exportButton)
            self.toolbar.add(self.statusLabel)
            self.tabbedPane = swing.JTabbedPane()
            self.logTextArea = swing.JTextArea()
            self.logTextArea.setEditable(False)
            self.logScrollPane = swing.JScrollPane(self.logTextArea)
            self.tableModel = DefaultTableModel([u"Timestamp", u"Token", u"Chat ID", u"HTTP URI"], 0)
            self.resultTable = swing.JTable(self.tableModel)
            # 启用表格列排序
            self.resultTable.setAutoCreateRowSorter(True)
            self.tableScrollPane = swing.JScrollPane(self.resultTable)
            self.tabbedPane.addTab("Logs", self.logScrollPane)
            self.tabbedPane.addTab("Results", self.tableScrollPane)
            self.panel.add(self.toolbar, BorderLayout.NORTH)
            self.panel.add(self.tabbedPane, BorderLayout.CENTER)
            self.clearButton.addActionListener(self.clear_all)
            self.refreshButton.addActionListener(self.refresh_status)
            self.exportButton.addActionListener(self.export_csv)
            self.update_ui(u"UI 初始化成功。")
            debug("UIManager 初始化成功。")
        except Exception as e:
            debug("UIManager 初始化异常: " + str(e))
    
    def get_ui_component(self):
        return self.panel
    
    def update_ui(self, message):
        try:
            self.logTextArea.append(message + u"\n")
            self.statusLabel.setText(u"Status: " + datetime.datetime.now().isoformat())
        except Exception as e:
            debug("更新UI日志异常: " + str(e))
    
    def add_result(self, timestamp, token, chatid, http_info):
        try:
            self.tableModel.addRow([timestamp, token, chatid, http_info])
        except Exception as e:
            debug("添加结果到UI表格异常: " + str(e))
    
    def clear_all(self, event):
        try:
            self.logTextArea.setText(u"")
            self.tableModel.setRowCount(0)
            self.statusLabel.setText(u"Status: Cleared at " + datetime.datetime.now().isoformat())
        except Exception as e:
            debug("清空UI异常: " + str(e))
    
    def refresh_status(self, event):
        try:
            self.statusLabel.setText(u"Status: Refreshed at " + datetime.datetime.now().isoformat())
        except Exception as e:
            debug("刷新状态栏异常: " + str(e))
    
    def export_csv(self, event):
        try:
            export_file = os.path.join(os.getcwd(), "TeleSnare_results.csv")
            with open(export_file, "wb") as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow([u"Timestamp".encode("utf-8"), u"Token".encode("utf-8"), u"Chat ID".encode("utf-8"), u"HTTP URI".encode("utf-8")])
                rowCount = self.tableModel.getRowCount()
                colCount = self.tableModel.getColumnCount()
                for row in range(rowCount):
                    rowData = []
                    for col in range(colCount):
                        cell = self.tableModel.getValueAt(row, col)
                        if isinstance(cell, unicode):
                            rowData.append(cell.encode("utf-8"))
                        else:
                            rowData.append(str(cell))
                    writer.writerow(rowData)
            self.update_ui(u"结果已导出到 " + export_file)
        except Exception as e:
            debug("导出CSV异常: " + str(e))
            self.update_ui(u"导出CSV异常: " + str(e))

##############################
# BurpExtender：整合所有模块，实现 IBurpExtender、IHttpListener 和 ITab 接口
##############################
class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        try:
            self.callbacks = callbacks
            self.helpers = callbacks.getHelpers()
            callbacks.setExtensionName("TeleSnare - Advanced Telegram Extractor")
            debug("扩展名称已设置。")
        except Exception as e:
            debug("设置扩展名称异常: " + str(e))
        
        try:
            self.config = ConfigManager()
            self.business_logic = BusinessLogic(self.config)
            self.result_manager = ResultManager(self.config)
            self.ui_manager = UIManager()
            debug("所有模块初始化成功。")
        except Exception as e:
            debug("模块初始化异常: " + str(e))
        
        try:
            callbacks.addSuiteTab(self)
            callbacks.registerHttpListener(self)
            debug("注册标签页和HTTP监听器成功。")
        except Exception as e:
            debug("注册扩展接口异常: " + str(e))
        
        # 用于避免重复记录的内部集合
        self.seen_credentials = set()
        self.ui_manager.update_ui(u"TeleSnare 插件已加载。")
        return
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        try:
            debug("processHttpMessage triggered, toolFlag: " + str(toolFlag))
            if not messageIsRequest:
                response = messageInfo.getResponse()
                if response:
                    response_str = self.helpers.bytesToString(response)
                    debug("处理响应，长度: " + str(len(response_str)))
                    tokens, chatids = self.business_logic.extract_credentials(response_str)
                    debug("提取到 tokens: " + str(tokens) + ", chatids: " + str(chatids))
                    
                    # 尝试提取来源 URI，使用重载方法分析请求详情
                    try:
                        http_service = messageInfo.getHttpService()
                        analyzedRequest = self.helpers.analyzeRequest(http_service, messageInfo.getRequest())
                        uri = analyzedRequest.getUrl().toString()
                    except Exception as e:
                        debug("提取URI异常: " + str(e))
                        uri = HTTP_PLACEHOLDER

                    # 分情况处理：token 与 chatid 同时存在；或只有 token；或只有 chatid
                    if tokens and chatids:
                        for token in tokens:
                            for chatid in chatids:
                                cred_key = (token, chatid)
                                if cred_key not in self.seen_credentials:
                                    self.seen_credentials.add(cred_key)
                                    msg = u"检测到 Telegram 凭证:\nToken: {0}\nChat ID: {1}\nURI: {2}".format(token, chatid, uri)
                                    self.ui_manager.update_ui(msg)
                                    timestamp = self.result_manager.add_result(token, chatid, uri)
                                    if timestamp:
                                        self.ui_manager.add_result(timestamp, token, chatid, uri)
                    elif tokens:
                        for token in tokens:
                            cred_key = (token, None)
                            if cred_key not in self.seen_credentials:
                                self.seen_credentials.add(cred_key)
                                msg = u"检测到 Telegram token:\nToken: {0}\nURI: {1}".format(token, uri)
                                self.ui_manager.update_ui(msg)
                                timestamp = self.result_manager.add_result(token, u"", uri)
                                if timestamp:
                                    self.ui_manager.add_result(timestamp, token, u"", uri)
                    elif chatids:
                        for chatid in chatids:
                            cred_key = (None, chatid)
                            if cred_key not in self.seen_credentials:
                                self.seen_credentials.add(cred_key)
                                msg = u"检测到 Telegram chat_id:\nChat ID: {0}\nURI: {1}".format(chatid, uri)
                                self.ui_manager.update_ui(msg)
                                timestamp = self.result_manager.add_result(u"", chatid, uri)
                                if timestamp:
                                    self.ui_manager.add_result(timestamp, u"", chatid, uri)
                    else:
                        debug("未匹配到任何凭证。")
                else:
                    debug("响应为空。")
        except Exception as e:
            error_msg = "处理HTTP消息时异常: " + str(e)
            debug(error_msg)
            self.ui_manager.update_ui(error_msg)
    
    # ITab 接口：返回标签页标题
    def getTabCaption(self):
        return "TeleSnare"
    
    # ITab 接口：返回自定义 UI 组件
    def getUiComponent(self):
        return self.ui_manager.get_ui_component()
