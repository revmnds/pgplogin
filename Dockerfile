FROM php:8.3-cli-alpine

RUN apk add --no-cache gnupg

WORKDIR /app
COPY pgplogin.php /app/pgplogin.php
COPY example /app/example

EXPOSE 8000
CMD ["php", "-S", "0.0.0.0:8000", "-t", "example"]
