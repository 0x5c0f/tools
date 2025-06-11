#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#################################################
#   author      0x5c0f
#   date        2024-07-19
#   email       mail@0x5c0f.cc
#   web         blog.0x5c0f.cc
#   version     2.3.0  (Optimized)
#   last update 2024-09-06
#   descript    由 Gemini 创建
#################################################

import time
import argparse
import os
import asyncio
from flask import Flask, request, Response, render_template_string
from prometheus_client import Gauge, generate_latest
from urllib.parse import urlparse
import websockets
import tempfile
import sqlite3
import threading
import logging
from datetime import datetime

# 设置日志记录器
# 改进日志配置，可以输出到文件或控制台，并设置不同的级别
logging.basicConfig(
    level=logging.INFO, # 默认级别改为 INFO，可以根据需要调整
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# 定义监控指标
# 移除 target 标签，使 probe_success 和 probe_duration_seconds 不再附加 target 标签
ws_status = Gauge('probe_success', 'Status of the WebSocket connection (1 for success, 0 for failure)')
ws_response_time = Gauge('probe_duration_seconds', 'Response time of the WebSocket connection')

# 创建线程局部存储对象
thread_local = threading.local()

# 定义数据最大存储记录
MAX_RECORDS = 1000

# HTML 模板，用于改进 web 界面
HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
    <head>
        <title>WebSocket Health Check</title>
        <style>
            body { font-family: sans-serif; margin: 20px; }
            h1, h2 { color: #333; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            .success { color: green; font-weight: bold; }
            .failed { color: red; font-weight: bold; }
            .info { margin-bottom: 20px; }
            code { background-color: #eee; padding: 2px 4px; border-radius: 3px; }
        </style>
    </head>
    <body>
        <h1>WebSocket Health Check</h1>
        <div class="info">
            <p>使用 <code>/probe</code> 端点检查 WebSocket 连接。</p>
            <p>示例: <code><a href="/probe?target=ws://echo.websocket.org">/probe?target=ws://echo.websocket.org</a></code></p>
            <p>Prometheus Metrics: <code><a href="/metrics">/metrics</a></code> (此端点通常由 Prometheus 抓取)</p>
        </div>
        <h2>最近的检查结果 (最近 {{ results|length }} 条记录):</h2>
        <table>
            <thead>
                <tr>
                    <th>目标</th>
                    <th>状态</th>
                    <th>响应时间 (秒)</th>
                    <th>时间戳</th>
                    <th>错误信息</th>
                </tr>
            </thead>
            <tbody>
                {% for result in results %}
                <tr>
                    <td>{{ result['target'] }}</td>
                    <td class="{{ 'success' if result['status'] == 'Success' else 'failed' }}">{{ result['status'] }}</td>
                    <td>{{ "%.4f"|format(result['response_time']) if result['response_time'] is not none else 'N/A' }}</td>
                    <td>{{ result['timestamp'] }}</td>
                    <td>{{ result['error'] if result['error'] else '无' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
    </body>
</html>
"""


class DatabaseHandler:
    def __init__(self):
        self.db_file = os.path.join(tempfile.gettempdir(), 'ws_results.db')
        # 初始化时确保数据库文件存在且表已创建
        self._initialize_db()

    def _initialize_db(self):
        conn = None
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target TEXT NOT NULL,
                status TEXT NOT NULL,
                response_time REAL,
                timestamp TEXT NOT NULL,
                error TEXT
            )
            ''')
            conn.commit()
            logger.info(f"Database initialized at {self.db_file}")
        except sqlite3.Error as e:
            logger.error(f"Error initializing database: {e}")
        finally:
            if conn:
                conn.close()

    def get_conn_and_cursor(self):
        # 针对每个线程创建独立的连接
        if not hasattr(thread_local, 'conn') or not hasattr(thread_local, 'cursor'):
            try:
                thread_local.conn = sqlite3.connect(self.db_file)
                thread_local.cursor = thread_local.conn.cursor()
            except sqlite3.Error as e:
                logger.error(f"Error creating thread-local database connection: {e}")
                return None, None
        return thread_local.conn, thread_local.cursor

    def add_result(self, result):
        conn, cursor = self.get_conn_and_cursor()
        if conn is None or cursor is None:
            logger.error("Failed to get database connection and cursor for adding result.")
            return
        try:
            cursor.execute('''
            INSERT INTO results (target, status, response_time, timestamp, error)
            VALUES (?,?,?,?,?)
            ''', (result['target'], result['status'], result['response_time'], result['timestamp'], result.get('error')))
            conn.commit()

            # 保持结果数量为 MAX_RECORDS
            # 优化：只在记录数超过 MAX_RECORDS 时才执行删除
            cursor.execute('SELECT COUNT(*) FROM results')
            count = cursor.fetchone()[0]
            if count > MAX_RECORDS:
                # 删除最旧的记录，直到只剩下 MAX_RECORDS 条
                cursor.execute('DELETE FROM results WHERE id IN (SELECT id FROM results ORDER BY id ASC LIMIT ?)', (count - MAX_RECORDS,))
                conn.commit()
                logger.debug(f"Trimmed database, current records: {MAX_RECORDS}")

        except sqlite3.Error as e:
            logger.error(f"Error adding result to database: {e}")
        except Exception as e:
            logger.error(f"Unexpected error in add_result: {e}")


    def get_results(self, limit=MAX_RECORDS):
        conn, cursor = self.get_conn_and_cursor()
        if conn is None or cursor is None:
            logger.error("Failed to get database connection and cursor for getting results.")
            return []
        try:
            cursor.execute('SELECT target, status, response_time, timestamp, error FROM results ORDER BY id DESC LIMIT ?', (limit,))
            results = cursor.fetchall()
            return [
                {
                    "target": row[0],
                    "status": row[1],
                    "response_time": row[2],
                    "timestamp": row[3],
                    "error": row[4]
                }
                for row in results
            ]
        except sqlite3.Error as e:
            logger.error(f"Error fetching results from database: {e}")
            return []


# 全局数据库处理器实例
database_handler = DatabaseHandler()


@app.route('/')
def index():
    # 获取最近 30 条记录在网页上显示
    results = database_handler.get_results(limit=30)
    return render_template_string(HTML_TEMPLATE, results=results)

@app.route('/metrics')
def metrics():
    """Prometheus 抓取端点"""
    return Response(generate_latest(), mimetype='text/plain; version=0.0.4')


@app.route('/probe', methods=['GET'])
async def probe():
    """
    WebSocket 健康检查端点。
    注意：使用 async def 使其成为异步视图。
    """
    ws_url = request.args.get('target')
    if not ws_url:
        logger.warning("Missing 'target' parameter in probe request.")
        return "Missing 'target' parameter", 422

    # 验证 WebSocket URL
    parsed_url = urlparse(ws_url)
    if parsed_url.scheme not in ["ws", "wss"]:
        logger.warning(f"Invalid scheme '{parsed_url.scheme}' for target: {ws_url}")
        return f"Invalid scheme {parsed_url.scheme}. Only 'ws' and 'wss' are supported.", 422
    if not parsed_url.hostname:
        logger.warning(f"Invalid hostname for target: {ws_url}")
        return "Invalid hostname.", 422

    status_str = "Failed"
    response_time_val = 0.0
    error_message = None
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        start = time.monotonic() # 使用 monotonic_time 避免系统时间跳变的影响
        # 设置连接超时，避免长时间阻塞
        async with websockets.connect(ws_url, open_timeout=5) as websocket: # 5秒连接超时
            status_str = "Success"
            response_time_val = time.monotonic() - start
            ws_status.set(1)  # 设置为 1 表示连接成功，不带 target 标签
            ws_response_time.set(response_time_val) # 不带 target 标签
            logger.info(f"WebSocket connection to {ws_url} successful. Response time: {response_time_val:.4f}s")

    except websockets.exceptions.WebSocketException as e:
        error_message = f"WebSocket error: {e}"
        logger.error(f"WebSocket connection to {ws_url} failed: {error_message}")
        ws_status.set(0)  # 设置为 0 表示连接失败，不带 target 标签
        ws_response_time.set(0) # 不带 target 标签
    except ConnectionRefusedError:
        error_message = "Connection refused."
        logger.error(f"WebSocket connection to {ws_url} refused: {error_message}")
        ws_status.set(0) # 不带 target 标签
        ws_response_time.set(0) # 不带 target 标签
    except TimeoutError:
        error_message = "Connection timed out."
        logger.error(f"WebSocket connection to {ws_url} timed out: {error_message}")
        ws_status.set(0) # 不带 target 标签
        ws_response_time.set(0) # 不带 target 标签
    except Exception as e:
        error_message = f"Unexpected error: {e}"
        logger.error(f"Unexpected error during WebSocket check for {ws_url}: {error_message}")
        ws_status.set(0) # 不带 target 标签
        ws_response_time.set(0) # 不带 target 标签

    result = {
        "target": ws_url,
        "status": status_str,
        "response_time": response_time_val,
        "timestamp": timestamp,
        "error": error_message
    }

    # 将结果添加到数据库
    database_handler.add_result(result)

    # 返回 Prometheus 格式的响应
    return Response(generate_latest(), mimetype='text/plain; version=0.0.4')


def main():
    parser = argparse.ArgumentParser(description='WebSocket health check script for Prometheus')
    parser.add_argument('--port', type=int, default=8000, help='The port to expose metrics for Prometheus (default: 8000)')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='The host to bind the Flask app to (default: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', help='Enable Flask debug mode (reloads on code changes, shows debug info)')
    args = parser.parse_args()

    logger.info(f"Starting WebSocket health check server on {args.host}:{args.port}")
    if args.debug:
        logger.warning("Flask debug mode is enabled. Do NOT use in production!")

    # 启动 Flask HTTP 服务器
    # 使用 threaded=False (默认)，因为 probe 端点现在是 async，由 Flask 内部的 asyncio 循环处理并发
    # 如果要生产部署，通常使用 Gunicorn 或 uWSGI 运行 Flask 应用，它们会处理并发和进程管理
    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == '__main__':
    # 在主线程中初始化数据库连接 (如果需要)
    # 确保在任何线程使用之前完成
    main()