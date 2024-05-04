# Usar la imagen oficial de PostgreSQL como base
FROM postgres:latest

# Establecer variables de entorno
ENV POSTGRES_DB=authenticator
ENV POSTGRES_USER=auth
ENV POSTGRES_PASSWORD=queso123

# Copiar los scripts de migración al directorio que se ejecuta al inicializar la base de datos
COPY ./migrations/ /docker-entrypoint-initdb.d/
