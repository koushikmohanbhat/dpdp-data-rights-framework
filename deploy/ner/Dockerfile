# NER sidecar for the remote_ner detector (docs/pii-benchmark.md#ner-sidecar).
# Bakes the model into the image so the container runs with no internet access.
#
#   DOCKER_BUILDKIT=1 docker build --secret id=hf_token,env=HF_TOKEN -f deploy/ner/Dockerfile -t dpdp-ner:indicner .
#   docker run --rm -e NER_HOST=0.0.0.0 -p 127.0.0.1:8081:8081 dpdp-ner:indicner     # local try-out
# In an ECS task or Kubernetes pod the containers share localhost: keep the default NER_HOST=127.0.0.1.
#
# MODEL can be any Hugging Face token-classification model, or a path under the build context.
# ai4bharat/IndicNER is gated: accept its terms on Hugging Face, then pass a read token as the secret above
# (never as a build arg; secrets are not stored in any layer).
FROM python:3.12-slim AS model
ARG MODEL=ai4bharat/IndicNER
RUN pip install --no-cache-dir "huggingface_hub>=0.24"
RUN --mount=type=secret,id=hf_token,required=false \
    HF_TOKEN="$(cat /run/secrets/hf_token 2>/dev/null || true)" \
    python -c "import os,sys; from huggingface_hub import snapshot_download; \
snapshot_download(sys.argv[1], local_dir='/models/ner', token=os.environ.get('HF_TOKEN') or None, \
allow_patterns=['*.json','*.txt','*.model','*.safetensors','*.bin'])" "$MODEL"

FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
    OMP_NUM_THREADS=2 TOKENIZERS_PARALLELISM=false
WORKDIR /app
# CPU-only torch keeps the image small; IndicNER (BERT-base size) runs at tens of milliseconds per message on CPU.
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu "torch>=2.2"
COPY pyproject.toml README.md LICENSE NOTICE ./
COPY src ./src
RUN pip install --no-cache-dir ".[indic-ner,api]" \
 && useradd --uid 10002 --create-home --shell /usr/sbin/nologin ner
COPY --from=model --chown=10002 /models/ner /models/ner
USER 10002
EXPOSE 8081
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8081/healthz')"
ENV NER_HOST=127.0.0.1
ENTRYPOINT ["sh", "-c", "exec dpdp-rights ner-serve --model /models/ner --host \"$NER_HOST\" --port 8081"]
