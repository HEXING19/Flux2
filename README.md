# Flux XDR

Flux 是一个基于 LLM 的智能安全运营平台，支持：
- 联动码/AKSK 登录
- 多模型连接池（OpenAI/智谱/DeepSeek/自定义）
- OOP Skills + 缺参追问 + 上下文序号映射
- SSE 流式对话与多模态 payload 渲染
- Workflow DAG + Cron + 人工审批闭环

## 运行

推荐先创建虚拟环境（避免全局 Python 依赖冲突）：

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=$(pwd)/backend
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

打开 [http://127.0.0.1:8000](http://127.0.0.1:8000)

## 测试

先确保已安装依赖，并且使用 `python3`：

```bash
source .venv/bin/activate
pip install -r requirements.txt
export PYTHONPATH=$(pwd)/backend
python3 -m unittest discover -s backend/app/tests -p 'test_*.py'
```

只跑某一个测试文件：

```bash
source .venv/bin/activate
export PYTHONPATH=$(pwd)/backend
python3 -m unittest backend/app/tests/test_workflow.py
```

如果你遇到 `ModuleNotFoundError`（例如 `sqlmodel`/`pydantic_settings`），通常是依赖还没装到当前环境，重新执行：

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

## Docker 部署与验证

`Dockerfile` 基于 `python:3.12-slim`，不会遇到本机 Python 3.9 的 `str | None` 类型语法报错。

首次使用（或之前把 `flux.db` 误创建成目录）先执行：

```bash
rm -rf flux.db
mkdir -p data
```

启动服务：

```bash
docker compose up --build -d
docker compose logs -f
```

访问： [http://127.0.0.1:8000](http://127.0.0.1:8000)

说明：数据库文件会持久化到宿主机 `./data/flux.db`（compose 内为 `/app/data/flux.db`）。

在 Docker 内跑全量测试：

```bash
docker compose run --rm flux python -m unittest discover -s backend/app/tests -p 'test_*.py'
```

停止服务：

```bash
docker compose down
```

## 一键交付

- PyInstaller: `./scripts/build_pyinstaller.sh`
- Docker: `docker compose up --build`



cd /Users/hexing/Flux2
docker compose down
rm -rf flux.db
mkdir -p data
docker compose up --build -d
docker compose logs -f