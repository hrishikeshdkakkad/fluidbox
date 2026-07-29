#!/usr/bin/env bash
# The "dangerous" action the demo policy gates behind human approval.
# In this fixture it releases nothing real: it appends one line to deploy.log
# so the receipt can show exactly what an approval did (and a denial didn't).
line="[deploy] $(date -u +%FT%TZ) released demo build to demo-target"
echo "$line" >> deploy.log
echo "$line"
