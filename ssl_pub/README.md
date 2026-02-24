# 脚本是调用 [certd/certd](https://github.com/certd/certd) 接口，下载相关证书并重启本地相关应用, 脚本由 CodeX 最终完善

## 使用方式
```shell
$> pip install -r requirements.txt
$> cp config.yaml.example config.yaml 
$> python update.ssl.py
```

## 配置项说明
```ini
# 以下简单说明核心参数，其他配置查看 config.yaml.example

certd_base_url: "https://ssl.example.com"                     # Certd服务地址
certd_key_id: ""                                              # API密钥ID
certd_key_secret: ""                                          # API密钥密钥

serverinfo: "xxx-00.00.00.00"                                 # 服务器信息，用于标注更新来源那个节点 

cert_ids:                                                     # 要获取的证书ID列表(对应证书仓库中对应的ID)
  - 1                                                         # example.com

# 通知（Apprise URL 列表）
apprise_urls:
  - "tgram://BOT_TOKEN/CHAT_ID"
  - "wecombot://BotKey"


# domain_reload_commands:                                       # 各域名对应的重启命令
#   "example.com": "systemctl restart nginx"                    # 明文命令
```

说明：
- `notification_title` 可自定义通知标题，默认 `服务器证书更新监控`
