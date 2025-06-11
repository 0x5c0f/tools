# FROM registry.cn-chengdu.aliyuncs.com/0x5c0f/python:3.11-alpine
FROM python:3.11-alpine

WORKDIR /usr/src/app

COPY . .

RUN pip install --no-cache-dir -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple

CMD [ "gunicorn","-w","4","-k", "gthread","-b","0.0.0.0:8000","websocket-cli-check:app" ]
# CMD [ "gunicorn","-b","0.0.0.0:8000","websocket-cli-check:app" ]
