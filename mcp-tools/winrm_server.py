#!/usr/bin/env python3
"""
WinRM MCP Server
通过WinRM协议远程管理Windows服务器的MCP工具
pip install pywinrm mcp
"""

import asyncio
import json
from typing import Optional, Dict, Any
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import winrm
from winrm.protocol import Protocol


class WinRMServer:
    def __init__(self):
        self.server = Server("winrm-server")
        self.session: Optional[winrm.Session] = None
        self.config: Optional[Dict[str, Any]] = None
        
        # 注册工具处理器
        self.setup_handlers()
    
    def setup_handlers(self):
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            return [
                Tool(
                    name="winrm_configure",
                    description="配置WinRM连接参数（主机地址、用户名、密码等）",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "host": {
                                "type": "string",
                                "description": "Windows服务器的IP地址或主机名"
                            },
                            "username": {
                                "type": "string",
                                "description": "登录用户名"
                            },
                            "password": {
                                "type": "string",
                                "description": "登录密码"
                            },
                            "port": {
                                "type": "number",
                                "description": "WinRM端口（默认5985用于HTTP，5986用于HTTPS）",
                                "default": 5985
                            },
                            "transport": {
                                "type": "string",
                                "enum": ["plaintext", "ssl", "ntlm", "kerberos"],
                                "description": "传输协议类型",
                                "default": "ntlm"
                            }
                        },
                        "required": ["host", "username", "password"]
                    }
                ),
                Tool(
                    name="winrm_execute_powershell",
                    description="在远程Windows服务器上执行PowerShell命令",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "要执行的PowerShell命令"
                            }
                        },
                        "required": ["command"]
                    }
                ),
                Tool(
                    name="winrm_execute_cmd",
                    description="在远程Windows服务器上执行CMD命令",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "command": {
                                "type": "string",
                                "description": "要执行的CMD命令"
                            }
                        },
                        "required": ["command"]
                    }
                ),
                Tool(
                    name="winrm_get_services",
                    description="获取Windows服务列表",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filter": {
                                "type": "string",
                                "description": "服务名称过滤器（可选，支持通配符*）"
                            }
                        }
                    }
                ),
                Tool(
                    name="winrm_manage_service",
                    description="管理Windows服务（启动、停止、重启）",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "service_name": {
                                "type": "string",
                                "description": "服务名称"
                            },
                            "action": {
                                "type": "string",
                                "enum": ["start", "stop", "restart"],
                                "description": "要执行的操作"
                            }
                        },
                        "required": ["service_name", "action"]
                    }
                ),
                Tool(
                    name="winrm_get_processes",
                    description="获取正在运行的进程列表",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "filter": {
                                "type": "string",
                                "description": "进程名称过滤器（可选）"
                            }
                        }
                    }
                ),
                Tool(
                    name="winrm_get_system_info",
                    description="获取系统信息（操作系统、CPU、内存、磁盘等）",
                    inputSchema={
                        "type": "object",
                        "properties": {}
                    }
                ),
                Tool(
                    name="winrm_get_event_logs",
                    description="获取Windows事件日志",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "log_name": {
                                "type": "string",
                                "description": "日志名称（如Application, System, Security）",
                                "default": "System"
                            },
                            "max_events": {
                                "type": "number",
                                "description": "最多返回的事件数量",
                                "default": 10
                            }
                        }
                    }
                ),
                Tool(
                    name="winrm_copy_file",
                    description="将本地文件复制到远程Windows服务器",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "local_path": {
                                "type": "string",
                                "description": "本地文件路径"
                            },
                            "remote_path": {
                                "type": "string",
                                "description": "远程目标路径"
                            }
                        },
                        "required": ["local_path", "remote_path"]
                    }
                )
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Any) -> list[TextContent]:
            try:
                if name == "winrm_configure":
                    return await self.configure_connection(arguments)
                elif name == "winrm_execute_powershell":
                    return await self.execute_powershell(arguments)
                elif name == "winrm_execute_cmd":
                    return await self.execute_cmd(arguments)
                elif name == "winrm_get_services":
                    return await self.get_services(arguments)
                elif name == "winrm_manage_service":
                    return await self.manage_service(arguments)
                elif name == "winrm_get_processes":
                    return await self.get_processes(arguments)
                elif name == "winrm_get_system_info":
                    return await self.get_system_info()
                elif name == "winrm_get_event_logs":
                    return await self.get_event_logs(arguments)
                elif name == "winrm_copy_file":
                    return await self.copy_file(arguments)
                else:
                    raise ValueError(f"未知工具: {name}")
            except Exception as e:
                return [TextContent(type="text", text=f"错误: {str(e)}")]
    
    async def configure_connection(self, args: Dict[str, Any]) -> list[TextContent]:
        """配置WinRM连接"""
        host = args["host"]
        username = args["username"]
        password = args["password"]
        port = args.get("port", 5985)
        transport = args.get("transport", "ntlm")
        
        # 构建连接URL
        if transport == "ssl":
            endpoint = f"https://{host}:{port}/wsman"
        else:
            endpoint = f"http://{host}:{port}/wsman"
        
        try:
            self.session = winrm.Session(
                endpoint,
                auth=(username, password),
                transport=transport,
                server_cert_validation='ignore'
            )
            
            self.config = {
                "host": host,
                "username": username,
                "port": port,
                "transport": transport
            }
            
            # 测试连接（使用禁用进度条的命令）
            result = self.session.run_ps("$ProgressPreference = 'SilentlyContinue'; Write-Output 'Connection Test'")
            if result.status_code == 0:
                message = (
                    f"✓ WinRM连接配置成功！\n\n"
                    f"主机: {host}\n"
                    f"用户: {username}\n"
                    f"端口: {port}\n"
                    f"传输: {transport}\n"
                    f"状态: 连接正常"
                )
            else:
                message = f"连接配置完成，但测试失败: {result.std_err.decode()}"
                
            return [TextContent(type="text", text=message)]
        except Exception as e:
            return [TextContent(type="text", text=f"连接失败: {str(e)}")]
    
    def _clean_clixml_error(self, error: str) -> str:
        """清理CLIXML格式的进度/状态信息"""
        if not error:
            return ""
        
        # 如果是CLIXML格式的进度或状态信息，过滤掉
        if error.startswith('#< CLIXML'):
            # 检查是否包含真正的错误信息
            # 进度信息通常包含 S="progress" 或 "Preparing modules"
            if 'S="progress"' in error or 'Preparing modules' in error:
                return ""
            # 如果包含 S="Error"，则保留（这是真正的错误）
            if 'S="Error"' in error:
                # 尝试提取错误信息（简化处理）
                return error
        
        return error
    
    async def execute_powershell(self, args: Dict[str, Any]) -> list[TextContent]:
        """执行PowerShell命令"""
        if not self.session:
            return [TextContent(type="text", text="错误: 请先使用 winrm_configure 配置连接")]
        
        command = args["command"]
        
        # 在命令前添加禁用进度条和错误流的设置
        # 这是从源头上防止CLIXML进度信息出现的最佳实践
        wrapped_command = f"""
$ProgressPreference = 'SilentlyContinue'
$ErrorActionPreference = 'Continue'
{command}
"""
        
        try:
            result = self.session.run_ps(wrapped_command)
            output = result.std_out.decode('utf-8', errors='replace').strip()
            error = result.std_err.decode('utf-8', errors='replace').strip()
            
            # 过滤掉可能残留的PowerShell进度信息（CLIXML格式）
            error = self._clean_clixml_error(error)
            
            # 如果命令执行失败（退出码非0），才认为是错误
            if result.status_code != 0:
                response = f"❌ 命令执行失败 (退出码: {result.status_code})\n\n"
                if output:
                    response += f"输出:\n{output}\n\n"
                if error:
                    response += f"错误信息:\n{error}"
            else:
                # 命令执行成功
                if output:
                    response = f"✓ 执行成功\n\n{output}"
                else:
                    response = "✓ 命令执行成功（无输出）"
            
            return [TextContent(type="text", text=response)]
        except Exception as e:
            return [TextContent(type="text", text=f"执行失败: {str(e)}")]
    
    async def execute_cmd(self, args: Dict[str, Any]) -> list[TextContent]:
        """执行CMD命令"""
        if not self.session:
            return [TextContent(type="text", text="错误: 请先使用 winrm_configure 配置连接")]
        
        command = args["command"]
        
        try:
            result = self.session.run_cmd(command)
            output = result.std_out.decode('utf-8', errors='replace').strip()
            error = result.std_err.decode('utf-8', errors='replace').strip()
            
            # 如果命令执行失败（退出码非0），才认为是错误
            if result.status_code != 0:
                response = f"❌ 命令执行失败 (退出码: {result.status_code})\n\n"
                if output:
                    response += f"输出:\n{output}\n\n"
                if error:
                    response += f"错误信息:\n{error}"
            else:
                # 命令执行成功
                if output:
                    response = f"✓ 执行成功\n\n{output}"
                else:
                    response = "✓ 命令执行成功（无输出）"
            
            return [TextContent(type="text", text=response)]
        except Exception as e:
            return [TextContent(type="text", text=f"执行失败: {str(e)}")]
    
    async def get_services(self, args: Dict[str, Any]) -> list[TextContent]:
        """获取服务列表"""
        filter_name = args.get("filter", "*")
        command = f"Get-Service -Name '{filter_name}' | Select-Object Name, Status, DisplayName | Format-Table -AutoSize"
        return await self.execute_powershell({"command": command})
    
    async def manage_service(self, args: Dict[str, Any]) -> list[TextContent]:
        """管理服务"""
        service_name = args["service_name"]
        action = args["action"]
        
        action_map = {
            "start": f"Start-Service -Name '{service_name}'",
            "stop": f"Stop-Service -Name '{service_name}' -Force",
            "restart": f"Restart-Service -Name '{service_name}' -Force"
        }
        
        if action not in action_map:
            return [TextContent(type="text", text=f"不支持的操作: {action}")]
        
        # 执行操作
        result = await self.execute_powershell({"command": action_map[action]})
        
        # 获取服务状态
        status_cmd = f"Get-Service -Name '{service_name}' | Select-Object Name, Status, DisplayName"
        status_result = await self.execute_powershell({"command": status_cmd})
        
        return [TextContent(
            type="text",
            text=f"服务 '{service_name}' {action} 操作已执行\n\n当前状态:\n{status_result[0].text}"
        )]
    
    async def get_processes(self, args: Dict[str, Any]) -> list[TextContent]:
        """获取进程列表"""
        filter_name = args.get("filter", "*")
        command = f"""
        Get-Process -Name '{filter_name}' -ErrorAction SilentlyContinue | 
        Select-Object Id, ProcessName, 
        @{{Name='CPU(s)';Expression={{[math]::Round($_.CPU, 2)}}}}, 
        @{{Name='Memory(MB)';Expression={{[math]::Round($_.WorkingSet / 1MB, 2)}}}} | 
        Format-Table -AutoSize
        """
        return await self.execute_powershell({"command": command})
    
    async def get_system_info(self) -> list[TextContent]:
        """获取系统信息"""
        command = """
        $os = Get-WmiObject -Class Win32_OperatingSystem
        $cpu = Get-WmiObject -Class Win32_Processor
        $disk = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3"
        
        Write-Output "=== 系统信息 ==="
        Write-Output "操作系统: $($os.Caption)"
        Write-Output "版本: $($os.Version)"
        Write-Output "架构: $($os.OSArchitecture)"
        Write-Output "安装日期: $($os.ConvertToDateTime($os.InstallDate))"
        Write-Output ""
        Write-Output "=== CPU信息 ==="
        Write-Output "名称: $($cpu.Name)"
        Write-Output "核心数: $($cpu.NumberOfCores)"
        Write-Output "逻辑处理器: $($cpu.NumberOfLogicalProcessors)"
        Write-Output ""
        Write-Output "=== 内存信息 ==="
        Write-Output "总内存: $([math]::Round($os.TotalVisibleMemorySize/1MB, 2)) GB"
        Write-Output "可用内存: $([math]::Round($os.FreePhysicalMemory/1MB, 2)) GB"
        Write-Output "已用内存: $([math]::Round(($os.TotalVisibleMemorySize - $os.FreePhysicalMemory)/1MB, 2)) GB"
        Write-Output ""
        Write-Output "=== 磁盘信息 ==="
        $disk | ForEach-Object {
            $usedSpace = [math]::Round(($_.Size - $_.FreeSpace) / 1GB, 2)
            $totalSpace = [math]::Round($_.Size / 1GB, 2)
            $freeSpace = [math]::Round($_.FreeSpace / 1GB, 2)
            $usedPercent = [math]::Round(($usedSpace / $totalSpace) * 100, 2)
            Write-Output "$($_.DeviceID) - 总空间: $totalSpace GB, 已用: $usedSpace GB ($usedPercent%), 可用: $freeSpace GB"
        }
        """
        return await self.execute_powershell({"command": command})
    
    async def get_event_logs(self, args: Dict[str, Any]) -> list[TextContent]:
        """获取事件日志"""
        log_name = args.get("log_name", "System")
        max_events = args.get("max_events", 10)
        
        command = f"""
        Get-EventLog -LogName {log_name} -Newest {max_events} | 
        Select-Object TimeGenerated, EntryType, Source, EventID, Message | 
        Format-Table -AutoSize -Wrap
        """
        return await self.execute_powershell({"command": command})
    
    async def copy_file(self, args: Dict[str, Any]) -> list[TextContent]:
        """复制文件到远程服务器"""
        if not self.session:
            return [TextContent(type="text", text="错误: 请先使用 winrm_configure 配置连接")]
        
        local_path = args["local_path"]
        remote_path = args["remote_path"]
        
        try:
            with open(local_path, 'rb') as f:
                content = f.read()
            
            # 使用PowerShell将内容写入远程文件
            import base64
            encoded_content = base64.b64encode(content).decode()
            
            command = f"""
            $content = [System.Convert]::FromBase64String('{encoded_content}')
            [System.IO.File]::WriteAllBytes('{remote_path}', $content)
            Write-Output "文件已成功复制到 {remote_path}"
            """
            
            return await self.execute_powershell({"command": command})
        except FileNotFoundError:
            return [TextContent(type="text", text=f"错误: 本地文件不存在: {local_path}")]
        except Exception as e:
            return [TextContent(type="text", text=f"复制失败: {str(e)}")]
    
    async def run(self):
        """运行服务器"""
        async with stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


async def main():
    server = WinRMServer()
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())