#!/bin/bash

# Configuration
BASE_URL="http://localhost:3001"
SCHEDULE_ENDPOINT="$BASE_URL/measles-vaccination-check/schedule"
RESULT_ENDPOINT_BASE="$BASE_URL/measles-vaccination-check/result"
MAX_RETRIES=100
SLEEP_SECONDS=6
ID_COUNT=10

# Concurrency Configuration
CONCURRENT_REQUESTS=1

# Function to run a single simulation flow
run_worker() {
    local worker_id=$1
    local prefix="[Worker $worker_id]"
    
    # Create a unique temp file for this worker
    local payload_file
    payload_file=$(mktemp)

    # Ensure cleanup happens for this worker even on failure
    trap 'rm -f "$payload_file"' EXIT

    # 1. Generate Request ID
    local request_id
    request_id=$(uuidgen)
    echo "$prefix Starting flow with Request ID: $request_id"

    # 2. Generate Payload Stream
    # We generate data specifically for this worker into its unique temp file
    echo "$prefix Generating $ID_COUNT UUIDs..."
    
    for ((i=1; i<=ID_COUNT; i++)); do uuidgen; done | \
    jq -R . | \
    jq -s --arg rid "$request_id" '{requestId: $rid, fileStateIds: .}' > "$payload_file"

    local file_size
    file_size=$(du -h "$payload_file" | cut -f1)
    echo "$prefix Payload generated ($file_size)"

    # 3. Send Schedule Request
    echo "$prefix Sending Schedule Request..."
    local http_code
    http_code=$(curl --write-out "%{http_code}" --silent --output /dev/null \
        --location "$SCHEDULE_ENDPOINT" \
        --header 'Content-Type: application/json' \
        --data @"$payload_file")

    if [ "$http_code" -ne 200 ]; then
        echo "$prefix Error: Failed to schedule. HTTP Code: $http_code"
        return 1
    fi
    echo "$prefix Request scheduled successfully."

    # 4. Poll for Results
    local result_url="$RESULT_ENDPOINT_BASE/$request_id"
    local count=0
    
    while [ $count -lt $MAX_RETRIES ]; do
        count=$((count+1))
        
        # Fetch result
        local response
        response=$(curl --silent --location "$result_url")
        
        # Parse Status
        local status
        status=$(echo "$response" | jq -r '.status')
        
        echo "$prefix Attempt $count/$MAX_RETRIES: Status is [$status]"

        if [ "$status" == "COMPLETED" ]; then
            echo "$prefix Computation Finished!"
            echo "$prefix Summary: $(echo "$response" | jq -c '{status: .status, match: .result.match}')"
            return 0
        elif [ "$status" == "FAILED" ]; then
            echo "$prefix Computation Failed!"
            local error_msg
            error_msg=$(echo "$response" | jq -r '.error // "Unknown error"')
            echo "$prefix Error Message: $error_msg"
            return 1
        elif [ "$status" == "PENDING" ]; then
            sleep $SLEEP_SECONDS
        else
            echo "$prefix Unknown status received: $status"
            return 1
        fi
    done

    # 5. Timeout
    echo "$prefix Error: Operation timed out."
    return 1
}

# --- Main Execution ---

echo "--- Starting Load Test with $CONCURRENT_REQUESTS concurrent requests ---"

pids=()

# Launch workers in background
for (( c=1; c<=CONCURRENT_REQUESTS; c++ )); do
    run_worker "$c" &
    pids+=($!)
done

echo "--- All workers started. PIDs: ${pids[*]} ---"

# Wait for all workers and check exit codes
global_exit_code=0

for pid in "${pids[@]}"; do
    if wait "$pid"; then
        echo "Process $pid finished successfully."
    else
        echo "Process $pid FAILED."
        global_exit_code=1
    fi
done

if [ $global_exit_code -eq 0 ]; then
    echo "--- SUCCESS: All concurrent requests completed successfully. ---"
    exit 0
else
    echo "--- FAILURE: One or more requests failed. ---"
    exit 1
fi