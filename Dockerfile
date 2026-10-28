# NOTE: written without access to Docker, so it has not been built or run. It only uses the standard library image.
FROM python:3.12-slim
RUN useradd --create-home --uid 10001 app
WORKDIR /app
COPY --chown=app:app . .
USER app
ENV BG_HOST=0.0.0.0 BG_PORT=8000 BG_DB_PATH=/home/app/brandguardian.db
EXPOSE 8000
CMD ["python", "-m", "brandguardian"]
