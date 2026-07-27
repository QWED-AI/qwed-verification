FROM python:3.11-slim:latest

USER root
ADD https://example.com/installer.tar.gz /tmp/installer.tar.gz
ENV API_SECRET_KEY=do-not-hardcode-secrets-in-docker
EXPOSE 22

RUN apt-get update && apt-get install -y curl
CMD ["python", "app.py"]
