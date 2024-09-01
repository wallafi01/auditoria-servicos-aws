# Construir a imagem Docker

docker build -t aws-audit-app .

# Rodar o container
docker run -e AWS_ACCESS_KEY_ID=<sua-access-key> \
           -e AWS_SECRET_ACCESS_KEY=<sua-secret-key> \
           -e AWS_REGION=<sua-região> \
           aws-audit-app
