FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.txt .
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --retries 10 --timeout 60 -r requirements.txt
COPY agent.py hbbs.py logs.py sniff.py ./
CMD ["python", "agent.py"]
