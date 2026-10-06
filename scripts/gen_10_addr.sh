# A simple bash loop to generate a batch of addresses for any secp256k1 chain
# select the chain type as required: [bitcoin, ethereum, tron, xrp]

for i in {0..9}; do
  echo "--- Index: $i ---"
  curl -s -X POST http://localhost:8080/api/v1/wallet/address \
    -H "Authorization: Bearer $MPC_API_TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"chain\": \"bitcoin\", \"account_index\": $i}" | jq .
done
