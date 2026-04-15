#!/bin/bash

# Configuration
API_URL="http://localhost:5050"
TIMESTAMP=$(date +%s)
TEST_POD="web-app-5d4dd47c87-hkqvs" # Use a known pod from previous kubectl get pods

echo "========================================="
echo "Testing LOTLGuard Quarantine & Search"
echo "========================================="

# 1. Inject a simulated attack
echo -e "\n[1] Injecting simulated attack for $TEST_POD..."
curl -s -X POST "$API_URL/api/action/simulate" \
  -H "Content-Type: application/json" \
  -d "{\"command\": \"cat /etc/shadow > /tmp/exfil_$TIMESTAMP\", \"pod\": \"$TEST_POD\"}" | python3 -m json.tool

# Wait for processor to pick it up
sleep 2

# 2. Trigger Quarantine
echo -e "\n[2] Triggering Quarantine for $TEST_POD..."
curl -s -X POST "$API_URL/api/action/quarantine_pod" \
  -H "Content-Type: application/json" \
  -d "{
    \"pod\": \"$TEST_POD\",
    \"threat_data\": {
      \"score\": 95,
      \"level\": \"Critical\",
      \"mitre_technique\": \"OS Credential Dumping\",
      \"mitre_id\": \"T1003\",
      \"commands\": [\"cat /etc/shadow > /tmp/exfil_$TIMESTAMP\"]
    }
  }" | python3 -m json.tool

# 3. Search Quarantine History
echo -e "\n[3] Searching Forensic History for '$TEST_POD'..."
SEARCH_RES=$(curl -s "$API_URL/api/quarantine/search?q=$TEST_POD")
echo "$SEARCH_RES" | python3 -m json.tool

# Extract ID
Q_ID=$(echo "$SEARCH_RES" | python3 -c "import sys, json; print(json.load(sys.stdin)['results'][0]['id'])")

if [ ! -z "$Q_ID" ]; then
    echo -e "\n✅ Found Quarantine Record with ID: $Q_ID"
else
    echo -e "\n❌ Failed to find quarantine record!"
    exit 1
fi

# 4. Check Native K8s Isolation
echo -e "\n[4] Checking Native K8s Isolation (Labels & NetPol)..."
echo "Labels on $TEST_POD:"
kubectl get pod $TEST_POD --show-labels | grep quarantined || echo "Label not found!"
echo "NetworkPolicies:"
kubectl get netpol quarantine-$TEST_POD || echo "NetworkPolicy not found!"

# 5. Release from Quarantine (COMMENTED OUT FOR UI VISIBILITY)
# echo -e "\n[5] Releasing $TEST_POD from quarantine (ID: $Q_ID)..."
# curl -s -X POST "$API_URL/api/quarantine/release/$Q_ID" | python3 -m json.tool

# 6. Final Check
# echo -e "\n[6] Final Cleanup Check..."
# kubectl get netpol quarantine-$TEST_POD && echo "❌ NetPol still exists!" || echo "✅ NetPol removed."

echo -e "\n========================================="
echo "Quarantine System Verification COMPLETE"
echo "========================================="
