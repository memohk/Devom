# Usar una imagen ligera de Python 3.12
FROM python:3.12-slim

# Establecer el directorio de trabajo dentro del contenedor
WORKDIR /app

# Instalar dependencias del sistema necesarias
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copiar el archivo de requerimientos e instalar dependencias de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar todo el código del proyecto al contenedor
COPY . .

# Crear carpetas necesarias si no existen
RUN mkdir -p uploads jwt_keys

# Exponer el puerto del banco
EXPOSE 8080

# Comando para iniciar el servidor
CMD ["python", "server.py"]
