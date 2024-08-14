#!/bin/sh

cp /app/.env.vite.prod /app/.env
exec "$@"