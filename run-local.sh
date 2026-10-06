#!/bin/bash

# 1. Determine the absolute path of the project root
# This ensures the script works no matter where you run it from
PROJECT_ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$PROJECT_ROOT"

echo "=========================================="
echo "Running from: $PROJECT_ROOT"
echo "=========================================="

# 2. Verify critical files exist BEFORE starting
if [ ! -f "./target/release/mpc-coordinator" ]; then
    echo "❌ Error: Binaries not found. Please run 'cargo build --release' first."
    exit 1
fi

if [ ! -f "config/coordinator.toml" ] || [ ! -f "config/node1.toml" ] || [ ! -f "config/node2.toml" ] || [ ! -f "config/node3.toml" ]; then
    echo "❌ Error: Config files not found in config/ directory."
    echo "   Expected: config/coordinator.toml, config/node1.toml, etc."
    exit 1
fi

if [ ! -f ".env" ]; then
    echo "⚠️  Warning: .env file not found. Creating a default one..."
    echo "DATABASE_URL=sqlite://mpc_wallet.db" > .env
fi

# Create logs directory
mkdir -p logs

echo "Starting Coordinator..."
./target/release/mpc-coordinator --config config/coordinator.toml > logs/coordinator.log 2>&1 &
PID_COORD=$!

sleep 2

echo "Starting Node 1..."
./target/release/mpc-node --config config/node1.toml > logs/node1.log 2>&1 &
PID_N1=$!

echo "Starting Node 2..."
./target/release/mpc-node --config config/node2.toml > logs/node2.log 2>&1 &
PID_N2=$!

echo "Starting Node 3..."
./target/release/mpc-node --config config/node3.toml > logs/node3.log 2>&1 &
PID_N3=$!

# echo "Starting API Gateway"
# (Added stdbuf -oL to force line-buffering):
stdbuf -oL ./target/release/mpc-api > logs/api.log 2>&1 &
PID_API=$!

#echo "Starting API Gateway..."
#./target/release/mpc-api > logs/api.log 2>&1 &
#PID_API=$!

echo "=========================================="
echo "Cluster is running!"
echo "To watch logs, run: tail -f logs/node1.log"
echo "Press Ctrl+C to stop all services."
echo "=========================================="

# Trap Ctrl+C to gracefully kill all background processes
# 2>/dev/null hides the "No such process" error if a service already crashed
trap "echo 'Stopping cluster...'; kill $PID_COORD $PID_N1 $PID_N2 $PID_N3 $PID_API 2>/dev/null; exit" INT

# Wait for all background processes
wait
