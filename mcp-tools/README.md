# 一些 `MCP Server` 服务插件
- `winrm_server.py`: 通过 `WinRM` 操作远程服务器, 该插件由`Claude Sonnet 4.5` 全程创建
    ```json
    // pip install pywinrm mcp
    {
        "mcpServers": {
            "winrm": {
            "command": "python",
            "args": ["winrm_server.py"]
            }
        }
    }
    ```
