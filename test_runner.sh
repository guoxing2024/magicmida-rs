#!/bin/bash
run_test() {
    local exe="$1"
    local timeout=30
    
    ./target/release/mida-cli.exe unpack '/d/Tools/RE/dumps/runtime/启动器.exe' --output "$exe" 2>&1 | grep -E "ERROR|WARN" > /dev/null
    if [ $? -eq 0 ]; then
        echo "COMPILE_ERROR"
        return 1
    fi
    
    "$exe" &
    local pid=$!
    
    for i in $(seq 1 $timeout); do
        if ! kill -0 $pid 2>/dev/null; then
            echo "CRASHED_AT_${i}s"
            return 1
        fi
        sleep 1
    done
    
    kill -9 $pid 2>/dev/null
    echo "SURVIVED_${timeout}s"
    return 0
}

run_test "test_baseline.exe"
