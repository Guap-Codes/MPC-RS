#!/bin/sh

# Ensure the config directory exists
mkdir -p ../config

# Create a temporary file for openssl extensions and ensure it's deleted on exit
EXT_FILE=$(mktemp)
trap "rm -f $EXT_FILE" EXIT

echo "Generating Root CA..."
openssl req -x509 -newkey rsa:4096 -days 365 -nodes \
  -keyout ../config/ca-key.pem -out ../config/ca-cert.pem \
  -subj "/CN=MPC-RS Root CA"

echo "Generating Coordinator cert..."
echo "subjectAltName=DNS:coordinator,DNS:localhost,IP:127.0.0.1" > "$EXT_FILE"
openssl req -newkey rsa:4096 -nodes \
  -keyout ../config/coordinator-key.pem -out ../config/coordinator.csr \
  -subj "/CN=coordinator"
openssl x509 -req -in ../config/coordinator.csr \
  -CA ../config/ca-cert.pem -CAkey ../config/ca-key.pem -CAcreateserial \
  -days 365 -out ../config/coordinator-cert.pem \
  -extfile "$EXT_FILE"

echo "Generating Node certs..."
for i in 1 2 3; do
  echo "subjectAltName=DNS:node${i},DNS:localhost,IP:127.0.0.1" > "$EXT_FILE"
  openssl req -newkey rsa:4096 -nodes \
    -keyout ../config/node${i}-key.pem -out ../config/node${i}.csr \
    -subj "/CN=node${i}"
  openssl x509 -req -in ../config/node${i}.csr \
    -CA ../config/ca-cert.pem -CAkey ../config/ca-key.pem -CAcreateserial \
    -days 365 -out ../config/node${i}-cert.pem \
    -extfile "$EXT_FILE"
done

echo "Generating Admin CLI cert..."
openssl req -newkey rsa:4096 -nodes \
  -keyout ../config/admin-key.pem -out ../config/admin.csr \
  -subj "/CN=admin"
openssl x509 -req -in ../config/admin.csr \
  -CA ../config/ca-cert.pem -CAkey ../config/ca-key.pem -CAcreateserial \
  -days 365 -out ../config/admin-cert.pem

echo "Generating API Gateway cert..."
echo "subjectAltName=DNS:mpc-api,DNS:localhost,IP:127.0.0.1" > "$EXT_FILE"
openssl req -newkey rsa:4096 -nodes \
  -keyout ../config/api-key.pem -out ../config/api.csr \
  -subj "/CN=mpc-api"
openssl x509 -req -in ../config/api.csr \
  -CA ../config/ca-cert.pem -CAkey ../config/ca-key.pem -CAcreateserial \
  -days 365 -out ../config/api-cert.pem \
  -extfile "$EXT_FILE"

echo "All certificates generated successfully in ../config/"
