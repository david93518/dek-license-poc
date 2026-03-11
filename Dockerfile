FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY license_server.py software_a.py software_b.py run_demo.py ./
COPY demo_input.txt ./

# 單一容器預設：python run_demo.py
# 三容器模式由 docker-compose 覆寫 command
CMD ["python", "run_demo.py"]
