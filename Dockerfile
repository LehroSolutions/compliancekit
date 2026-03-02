FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY compliancekit ./compliancekit
COPY webapp ./webapp
RUN pip install --no-cache-dir .
EXPOSE 5101
CMD ["python", "webapp/server.py"]
