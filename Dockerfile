# Runtime image intentionally excludes scan datasets and test code.
FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

COPY app/ ./app/
COPY schemas/ ./schemas/
COPY docker/entrypoint.sh /usr/local/bin/asa

RUN chmod 0555 /usr/local/bin/asa \
    && groupadd --system asa \
    && useradd --system --gid asa --home-dir /nonexistent --shell /usr/sbin/nologin asa \
    && mkdir -p /data /out \
    && chown asa:asa /data /out

USER asa:asa
VOLUME ["/data", "/out"]
ENTRYPOINT ["asa"]
CMD ["help"]

# Test image is separate; the runtime image remains small and does not include tests.
FROM runtime AS test
USER root
COPY tests/ ./tests/
RUN chown -R asa:asa /app/tests
USER asa:asa
CMD ["test"]
