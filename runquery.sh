#! /bin/bash
cat query.sql | bq query --use_legacy_sql=false --format=csv --parameter=domainkey:STRING:$DOMAINKEY --max_rows=100 | ./main.mjs
