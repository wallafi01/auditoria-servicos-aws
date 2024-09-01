# Usando uma imagem base do Python
FROM python:3.9-slim

# Diretório de trabalho dentro do container
WORKDIR /app

# Copiar o requirements.txt e instalar as dependências
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar o script para dentro do container
COPY aws_audit.py .

# Comando para rodar o script
CMD ["python", "aws_audit.py"]
