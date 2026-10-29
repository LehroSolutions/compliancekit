FROM python:3.11-slim
WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY compliancekit ./compliancekit
COPY webapp ./webapp
RUN pip install --no-cache-dir . \
    && useradd --create-home --uid 10001 compliancekit \
    && mkdir /data && chown compliancekit:compliancekit /data
# Fail closed: any APP_ENV other than development refuses to boot on the shipped default
# password or salt, so the image cannot come up with admin/admin123 by omission.
ENV APP_ENV=production APP_HOST=0.0.0.0 APP_DB_FILE=/data/data.sqlite APP_DATA_FILE=/data/data.json
VOLUME ["/data"]
USER compliancekit
EXPOSE 5101
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5101/api/ready', timeout=3)"
CMD ["python", "-m", "webapp.server"]
