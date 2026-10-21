#!/bin/bash
# ISSUE=8
# for i in `seq 1 19`;
# do
#   gh api \
#   -H "Accept: application/vnd.github+json" \
#   /repos/JLLeitschuh/security-research/issues/${ISSUE}/timeline\?page=${i}\&per_page=100 >> events/issue_${ISSUE}_page_${i}.json
# done  

# ISSUE=9
# for i in `seq 1 4`;
# do
#   gh api \
#   -H "Accept: application/vnd.github+json" \
#   /repos/JLLeitschuh/security-research/issues/${ISSUE}/timeline\?page=${i}\&per_page=100 >> events/issue_${ISSUE}_page_${i}.json
# done  

python3 process.py --folder events

# python3 process.py --data $data

# data=$(gh api \
#   -H "Accept: application/vnd.github+json" \
#   /repos/JLLeitschuh/security-research/issues/8/timeline\?page=2\&per_page=100)

# python3 process.py --data $data

# data=$(gh api \
#   -H "Accept: application/vnd.github+json" \
#   /repos/JLLeitschuh/security-research/issues/8/timeline\?page=3\&per_page=100)

# python3 process.py --data $data

# data=$(gh api \
#   -H "Accept: application/vnd.github+json" \
#   /repos/JLLeitschuh/security-research/issues/8/timeline\?page=4\&per_page=100)

# python3 process.py --data $data

# data=$(gh api \
#   -H "Accept: application/vnd.github+json" \
#   /repos/JLLeitschuh/security-research/issues/8/timeline\?page=5\&per_page=100)

# python3 process.py --data $data