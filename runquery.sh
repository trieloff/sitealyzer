#! /bin/bash
# use first argument as number of rows to fetch, default to 100
cat query.sql | bq query --use_legacy_sql=false --format=csv --parameter=domainkey:STRING:$DOMAINKEY --max_rows=${1:-100} | ./main.mjs