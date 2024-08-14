#!/bin/sh

cp /app/.env.vite.dev /app/.env
exec "$@"