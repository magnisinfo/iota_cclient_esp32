#!/bin/bash
cd ./uthash
git checkout -f f19dde22d80a563948a263afe00947e6e42ed8f4 --quiet
if [ $? -eq 0 ]; then
    git apply ../uthash_f19dde22d80a563948a263afe00947e6e42ed8f4.patch
else
    echo "$0 failed..."
fi
