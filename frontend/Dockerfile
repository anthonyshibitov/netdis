FROM node:20-alpine

WORKDIR /app
# ENV VITE_BACKEND=http://localhost:8000/
COPY . .
COPY entrypoint.dev.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]