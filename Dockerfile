FROM python:3.12-slim
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
RUN pip install --no-cache-dir ".[aws,openai,api,postgres]"
ENV DPDP_CONFIG=config/dpdp.aws.yaml
EXPOSE 8080
ENTRYPOINT ["sh", "-c", "dpdp-erasure -c $DPDP_CONFIG \"$@\"", "--"]
CMD ["serve", "--port", "8080"]
