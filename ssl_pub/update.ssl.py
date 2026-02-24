#!/opt/certd-client/.venv/bin/python
# -*- coding: utf-8 -*-
################################################# 
#   author      0x5c0f 
#   date        2025-08-20 
#   email       mail@0x5c0f.cc 
#   web         tools.0x5c0f.cc 
#   version     1.4.0
#   last update 2025-09-04
#   descript    <descript>
#################################################

# Switch to the script directory
# os.chdir(os.path.split(os.path.realpath(__file__))[0])

import yaml
import logging
import httpx
import json
import hashlib
import base64
import time
import subprocess
import re
from typing import Dict, List, Optional, Tuple
from pathlib import Path

import apprise
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# 获取脚本所在目录
script_dir = Path(__file__).parent
# os.chdir(os.path.split(os.path.realpath(__file__))[0])

class CertdClient:
    def __init__(self, config_path='config.yaml'):
        # 读取 YAML 配置
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        
        # 日志配置
        self.log_level = config.get("log_level", "INFO")
        self.log_format = config.get("log_format", "%(asctime)s - %(levelname)s - %(message)s")
        
        self.basedir = config.get("basedir", "/opt/update.ssl")
        self.serverinfo = config.get("serverinfo", "unknown_server")
        
        # Certd API 配置
        self.certd_base_url = config.get("certd_base_url", "http://127.0.0.1:7001").rstrip("/")
        self.certd_key_id = config.get("certd_key_id", "")
        self.certd_key_secret = config.get("certd_key_secret", "")
        
        # 证书配置
        self.cert_ids = config.get("cert_ids", [])
        self.cert_install_path = Path(self.basedir) / "certificates"

        self.domain_reload_commands = config.get("domain_reload_commands", {})
        
        # 通知配置
        self.notification_title = config.get("notification_title", "服务器证书更新监控")
        self.apprise_urls = config.get("apprise_urls", [])
        self.notification_body_format = str(config.get("notification_body_format", "markdown")).lower()
        
        # 证书格式配置
        self.cert_formats = config.get("cert_formats", ["crt", "key", "ic", "oc", "pfx", "der", "jks", "one"])
        
        # 初始化其他属性
        self.client = httpx.Client(timeout=30.0)

    def setup_logging(self):
        logging.basicConfig(
            level=getattr(logging, self.log_level.upper(), logging.INFO),
            format=self.log_format
        )

    def generate_token(self) -> str:
        """生成 Certd API 认证 token"""
        content = {
            "keyId": self.certd_key_id,
            "t": int(time.time()),
            "encrypt": False,
            "signType": "md5"
        }
        
        content_str = json.dumps(content, separators=(',', ':'), ensure_ascii=False)
        sign_str = content_str + self.certd_key_secret
        sign = hashlib.md5(sign_str.encode('utf-8')).hexdigest()
        
        content_b64 = base64.b64encode(content_str.encode('utf-8')).decode('utf-8')
        sign_b64 = base64.b64encode(sign.encode('utf-8')).decode('utf-8')
        
        return f"{content_b64}.{sign_b64}"


    def _render_notification(self, platform_name: str, domain: str, status: str, reason: str = "") -> str:
        emoji_map = {
            "成功": "✅",
            "失败": "❌",
            "警告": "⚠️",
            "跳过": "⚠️"
        }
        emoji = emoji_map.get(status.strip(), "")
        reason_block = f"\n> **备注：{reason}**" if reason else ""

        other_message = ""

        message = f"""
---------------------------------------------------
- **证书域名**：{domain}
- **操作状态**：{status} {emoji}
- **上报节点**：{self.serverinfo}
- **上报时间**：{time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())}{reason_block}
---------------------------------------------------
{other_message}"""

        return message.strip()

    def _get_apprise_format(self, markdown: bool):
        if markdown and self.notification_body_format != "text":
            return apprise.NotifyFormat.MARKDOWN
        return apprise.NotifyFormat.TEXT

    def send_notifications(self, content: str, markdown: bool = True) -> Dict[str, bool]:
        results = {}
        urls = self.apprise_urls if isinstance(self.apprise_urls, list) else []
        if not urls:
            logging.debug("未配置 apprise_urls，跳过通知发送。")
            return results

        body_format = self._get_apprise_format(markdown=markdown)

        for url in urls:
            notifier = apprise.Apprise()
            if not notifier.add(url):
                logging.error(f"[失败] 无法加载 Apprise 通知地址: {url}")
                results[url] = False
                continue

            try:
                ok = notifier.notify(
                    title=self.notification_title,
                    body=content,
                    body_format=body_format,
                )
                if ok:
                    logging.info(f"[成功] 已发送到: {url}")
                else:
                    logging.error(f"[失败] Apprise 通知发送失败: {url}")
                results[url] = ok
            except Exception as e:
                logging.error(f"[异常] {url} 通知发送失败: {e}")
                results[url] = False

        return results

    def extract_domains_from_cert(self, cert_content: str) -> Tuple[str, List[str]]:
        """从证书内容中提取域名"""
        try:
            cert = x509.load_pem_x509_certificate(cert_content.encode('utf-8'), default_backend())
            
            domains = []
            
            # 从 Subject 中提取 Common Name
            subject = cert.subject
            cn_attributes = subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
            if cn_attributes:
                cn = cn_attributes[0].value
                domains.append(cn)
            
            # 从 Subject Alternative Name 中提取域名
            try:
                san_extension = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                san_names = san_extension.value
                
                for name in san_names:
                    if isinstance(name, x509.DNSName):
                        domains.append(name.value)
            except x509.ExtensionNotFound:
                pass
            
            # 去重并保持顺序
            unique_domains = []
            seen = set()
            for domain in domains:
                if domain not in seen:
                    seen.add(domain)
                    unique_domains.append(domain)
            
            # 选择主域名（优先选择非通配符域名）
            primary_domain = unique_domains[0] if unique_domains else "unknown"
            for domain in unique_domains:
                if not domain.startswith('*.'):
                    primary_domain = domain
                    break
            
            return primary_domain, unique_domains
            
        except Exception as e:
            logging.error(f"解析证书域名时出错: {str(e)}")
            return "unknown", []

    def sanitize_filename(self, filename: str) -> str:
        """清理文件名中的非法字符"""
        illegal_chars = r'[<>:"/\\|?*]'
        sanitized = re.sub(illegal_chars, '_', filename)
        sanitized = sanitized.strip('. ')
        
        if not sanitized:
            sanitized = "certificate"
        
        return sanitized

    def get_certificate(self, cert_id: int) -> Optional[Dict]:
        """从 Certd API 获取证书"""
        try:
            token = self.generate_token()
            url = f"{self.certd_base_url}/api/v1/cert/get"
            
            headers = {
                "Content-Type": "application/json",
                "x-certd-token": token
            }
            
            data = {"certId": cert_id}
            
            response = self.client.post(url, json=data, headers=headers)
            response.raise_for_status()
            
            result = response.json()
            if result.get("code") != 0:
                raise Exception(f"API返回错误: {result.get('msg', '未知错误')}")
            
            return result.get("data", {})
            
        except Exception as e:
            error_message = f"获取证书 ID {cert_id} 失败: {e}"
            logging.error(error_message)
            
            msg = self._render_notification(
                platform_name="服务器证书更新监控",
                domain=f"证书 ID {cert_id}",
                status="失败",
                reason=error_message
            )
            self.send_notifications(msg)
            return None

    def _calculate_md5(self, data: str) -> str:
        """计算字符串的 MD5 值"""
        return hashlib.md5(data.encode('utf-8')).hexdigest()


    def save_certificate_files(self, cert_data: Dict, cert_id: int) -> bool:
        """保存证书文件到本地"""
        try:
            # 从证书中提取域名
            crt_content = cert_data.get("crt", "")
            if not crt_content:
                logging.error(f"证书 ID {cert_id} 中缺少 CRT 内容")
                return False
            
            primary_domain, all_domains = self.extract_domains_from_cert(crt_content)
            safe_domain = self.sanitize_filename(primary_domain)
            
            logging.info(f"证书 ID {cert_id} 提取到的域名:")
            logging.info(f"  主域名: {primary_domain}")
            logging.info(f"  所有域名: {', '.join(all_domains)}")
            
            # 创建域名目录
            domain_path = self.cert_install_path / safe_domain
            domain_path.mkdir(parents=True, exist_ok=True)
            
            # 文件命名规范映射
            # crt (完整证书链) -> fullchain.cer
            # key (私钥) -> 域名.key
            # 其他格式：域名+默认后缀
            file_mapping = {
                "oc": f"{safe_domain}.cer",
                "key": f"{safe_domain}.key",
                "crt": f"fullchain.cer",
                "ic": f"{safe_domain}.ic",
                "pfx": f"{safe_domain}.pfx",
                "der": f"{safe_domain}.der",
                "jks": f"{safe_domain}.jks",
                "one": f"{safe_domain}.one"
            }
            
            _updated = False
            # 保存各种格式的证书文件
            for format_type in self.cert_formats:
                cert_content = cert_data.get(format_type)
                if not cert_content:
                    continue
                
                # 获取文件名
                filename = file_mapping.get(format_type)
                if not filename:
                    continue
                
                # 直接构建文件路径，不处理冲突（直接覆盖）
                filepath = domain_path / filename
                
                if format_type == "crt":
                    _old_md5 = ""
                    if filepath.exists():
                        try:
                            old_content = filepath.read_text(encoding='utf-8')
                            _old_md5 = self._calculate_md5(old_content)
                        except Exception as e:
                            logging.warning(f"无法读取现有文件 {filepath} 来计算MD5: {e}")
                
                # 写入文件（直接覆盖已存在的文件）
                filepath.write_text(cert_content, encoding='utf-8')
                logging.info(f"成功保存 {format_type.upper()} 格式文件: {filepath}")
                
                # 仅对 crt 文件进行 MD5 对比
                if format_type == "crt":
                    new_md5 = self._calculate_md5(cert_content)
                    if _old_md5 and _old_md5 == new_md5:
                        logging.info(f"文件 {filepath} 内容未更改，MD5值相同。")
                    else:
                        logging.info(f"文件 {filepath} 内容已更新，MD5值不同。")
                        _updated = True
            
            # 保存域名信息文件
            info_filename = f"{safe_domain}_domains.txt"
            info_filepath = domain_path / info_filename
            
            info_content = (
                f"证书域名信息\n"
                f"================\n\n"
                f"证书ID: {cert_id}\n"
                f"主域名: {primary_domain}\n\n"
                f"所有域名:\n"
            )
            
            for i, domain in enumerate(all_domains, 1):
                info_content += f"{i}. {domain}\n"
            
            info_content += (
                f"\n证书获取时间: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"\n保存的证书文件:\n"
            )
            
            for format_type in self.cert_formats:
                if cert_data.get(format_type):
                    filename = file_mapping.get(format_type)
                    if filename:
                        info_content += f"- {filename}\n"
            
            # 写入域名信息文件（直接覆盖）
            info_filepath.write_text(info_content, encoding='utf-8')
            logging.info(f"成功保存域名信息文件: {info_filepath}")
            
            if _updated:
                logging.info(f"证书 ID {cert_id} 的文件已更新，准备重启相关服务。")
                _result, _status = self.restart_proxy(domain=primary_domain)
                if not _result and not _status:
                    logging.error(f"证书 '{primary_domain}' 更新未配置或包含错误指令，已跳过重启。")
                else:
                    msg = self._render_notification(
                        platform_name="服务器证书更新监控",
                        domain=primary_domain,
                        status="成功",
                        reason=f"证书更新已完成，请及时检查站点状态！"
                    )
                    self.send_notifications(msg)
            else:
                logging.info(f"证书 {primary_domain} 内容未更新，已跳过重启服务和发送通知。")
                
                if self.log_level == "DEBUG":
                    msg = self._render_notification(
                        platform_name="服务器证书更新监控",
                        domain=primary_domain,
                        status="跳过",
                        reason=f"未检查到新证书下发，已跳过重启。"
                    )
                    self.send_notifications(msg)
            
            return True
            
        except Exception as e:
            error_message = f"保存证书 ID {cert_id} 文件失败: {e}"
            logging.error(error_message)
            msg = self._render_notification(
                platform_name="服务器证书更新监控",
                domain=f"证书 ID {cert_id}",
                status="失败",
                reason=error_message
            )
            self.send_notifications(msg)
            return False

    def download_certificates(self):
        """下载所有配置的证书"""
        if not self.cert_ids:
            logging.warning("未配置证书 ID 列表，跳过下载。")
            return
        
        for cert_id in self.cert_ids:
            logging.info(f"正在获取证书 ID: {cert_id}")
            
            cert_data = self.get_certificate(cert_id)
            if cert_data:
                self.save_certificate_files(cert_data, cert_id)
            else:
                logging.error(f"获取证书 ID {cert_id} 失败")

    def close(self):
        self.client.close()

    def restart_proxy(self, domain: str):
        """重启代理服务"""
        command = self.domain_reload_commands.get(domain)
        
        if not command:
            logging.info(f"项目 '{domain}' 未配置重启命令，跳过重启。")
            return True, None
        
        if any(dangerous in command for dangerous in ['rm', 'format', 'del', 'dd', 'mkfs', 'shutdown', 'reboot', 'poweroff','init', 'halt', 'mv', 'chmod', 'chown', 'rmdir', 'wipe', 'fdisk', 'killall', 'su', 'curl', 'wget']):
            logging.error(f"拒绝执行可能危险的命令: {command}")
            return False, False

        if command:
            logging.info(f"开始执行 {domain} 项目重启任务，command: {command} ")
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True )

                logging.info("命令执行成功！")
                logging.debug("标准输出:\n%s", result.stdout)
                logging.debug("标准错误:\n%s", result.stderr)
                return True, "命令执行成功"
            except subprocess.CalledProcessError as e:
                logging.error(f"错误：命令执行失败，退出码: {e.returncode}")
                logging.debug("标准输出:\n%s" , e.stdout)
                logging.debug("标准错误:\n%s", e.stderr)
                return False, f"命令执行失败，退出码: {e.returncode}"
            except FileNotFoundError:
                logging.error("错误：'shell' 或命令未找到。")
                return False, "命令未找到"
            except Exception as e:
                logging.error(f"发生未知错误: {e}")
                return False, "未知错误"

def main():
    # 从YAML配置文件加载设置
    config_file = script_dir / "config.yaml"
    
    client = None
    try:
        client = CertdClient(config_file)
        client.setup_logging()
        
        client.download_certificates()
        
        # for domain in client.updated_domains:
        #     client.restart_proxy(domain)
            
    except FileNotFoundError as e:
        print(f"错误: {e}")
        print("请确保在脚本目录下存在 config.yaml 配置文件")
        exit(1)
    except yaml.YAMLError as e:
        print(f"配置文件格式错误: {e}")
        exit(1)
    except Exception as e:
        print(f"程序运行错误: {e}")
        exit(1)
    finally:
        if client:
            client.close()


if __name__ == "__main__":
    main()
