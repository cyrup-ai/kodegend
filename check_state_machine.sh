#!/bin/bash
cd /Users/davidmaple/kodegen-workspace/packages/kodegend

echo "Running cargo check..."
cargo check > /tmp/kodegend_check.log 2>&1
CHECK_EXIT=$?
echo "Cargo check exit code: $CHECK_EXIT" >> /tmp/kodegend_check.log

if [ $CHECK_EXIT -eq 0 ]; then
    echo "Running cargo clippy..."
    cargo clippy -- -D warnings > /tmp/kodegend_clippy.log 2>&1
    CLIPPY_EXIT=$?
    echo "Cargo clippy exit code: $CLIPPY_EXIT" >> /tmp/kodegend_clippy.log
else
    echo "Cargo check failed, skipping clippy" > /tmp/kodegend_clippy.log
    CLIPPY_EXIT=1
fi

echo "CHECK_EXIT=$CHECK_EXIT" > /tmp/kodegend_results.txt
echo "CLIPPY_EXIT=$CLIPPY_EXIT" >> /tmp/kodegend_results.txt
echo "DONE" >> /tmp/kodegend_results.txt
