#!/bin/bash

# LOTLGuard Real Attack Simulator v3.0
# Consolidated & Data-Driven

CSV_FILE="/home/kanchi/lotl-detection-framework/attack_simulation/attack_database.csv"
LOG_FILE="/home/kanchi/lotl-detection-framework/logs/falco_events.log"

echo "--------------------------------------------------------"
echo "🔥 LOTLGuard Attack Simulator v3.0 (Consolidated) 🔥"
echo "--------------------------------------------------------"

if [ ! -f "$CSV_FILE" ]; then
    echo "Error: $CSV_FILE not found!"
    exit 1
fi

# Function to simulate a Falco event
simulate_event() {
    local category=$1
    local name=$2
    local cmd=$3
    local risk=$4
    local pod=$5
    
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Mock some attacker IPs based on risk
    local ip="192.168.1.$((RANDOM % 254))"
    if [ "$risk" == "Critical" ]; then ip="45.33.22.$((RANDOM % 254))"; fi
    
    # Format as JSON for Falco simulation
    local event="{\"output\":\"$timestamp: $risk Attack $name detected in $pod. Command: $cmd\",\"priority\":\"$risk\",\"rule\":\"LOTL Detection v3\",\"time\":\"$timestamp\",\"container_id\":\"$(cat /proc/sys/kernel/random/uuid | cut -d'-' -f1)\",\"container_name\":\"$pod\",\"user\":\"root\",\"command\":\"$cmd\",\"source_ip\":\"$ip\",\"category\":\"$category\"}"
    
    echo "$event" >> "$LOG_FILE"
    echo "[$(date +%T)] [$risk] 🚀 Injecting $name into SOC Dashboard..."
    echo "            Target: $pod | Command: '$cmd'"
}

# Read CSV and skip header
tail -n +2 "$CSV_FILE" | while IFS=',' read -r category name cmd risk pod; do
    # Run the attack simulation
    simulate_event "$category" "$name" "$cmd" "$risk" "$pod"
    sleep 2
done

echo "--------------------------------------------------------"
echo "✅ All attacks from database simulated."
echo "--------------------------------------------------------"
