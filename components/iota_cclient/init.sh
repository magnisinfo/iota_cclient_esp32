#!/bin/bash
cd ./entangled
git checkout -f 47bc860fff572a8088a2ba2468c7291e458855bf --quiet
if [ $? -eq 0 ]; then
    git apply --whitespace=fix ../entangled_47bc860fff572a8088a2ba2468c7291e458855bf.patch
else
    echo "$0 failed..."
fi

cd -
/bin/bash ./gen_hash_container.sh

