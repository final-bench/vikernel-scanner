FROM python:3.12-slim
RUN pip install --no-cache-dir "huggingface_hub>=1.2"
RUN useradd -m -u 1000 user
WORKDIR /app
COPY --chown=1000 . /app
USER 1000
ENV HOME=/home/user PYTHONUNBUFFERED=1
EXPOSE 7860
CMD ["python", "server.py"]
