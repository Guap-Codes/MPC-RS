# Navigate to the config directory
cd ../config

# Generate a private key (used by the token issuer, e.g., your auth server)
openssl genrsa -out private.pem 2048

# Extract the public key (used by the API gateway to verify tokens)
openssl rsa -in private.pem -pubout -out public.pem

# Go back to the workspace root
cd ..
