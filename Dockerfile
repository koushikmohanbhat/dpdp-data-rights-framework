FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Choose the extras for your cloud: aws (default) or gcp, plus model providers.
#   docker build --build-arg EXTRAS=gcp,openai,anthropic,api,postgres,otel,auth .
ARG EXTRAS=aws,openai,anthropic,api,postgres,otel,auth
WORKDIR /app
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir ".[${EXTRAS}]" \
 && useradd --uid 10001 --create-home --shell /usr/sbin/nologin dpdp
USER 10001
# Config is not baked into the image: set DPDP_CONFIG to ssm://..., s3://... or a mounted file path.
ENV DPDP_CONFIG=/config/dpdp.yaml
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "exec dpdp-rights -c \"$DPDP_CONFIG\" \"$@\"", "--"]
CMD ["serve", "--port", "8080"]
