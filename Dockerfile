FROM python:3.11-slim
WORKDIR /app
COPY server.py ./server.py
ENV HOST=0.0.0.0 PORT=8787
EXPOSE 8787
CMD ["python3", "server.py"]
