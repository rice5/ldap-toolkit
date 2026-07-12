#!/bin/bash
#===============================================================================
# pre-commit hook — block commits containing sensitive patterns
#
# Install: cp tools/git-secrets-hook.sh .git/hooks/pre-commit
#
# Customize: add your company-specific patterns to the PATTERNS array below.
# This hook scans staged text files. Binary files are skipped.
#===============================================================================

PATTERNS=(
    # Private keys
    'BEGIN.*PRIVATE KEY'

    # Company domain / network (customize for your environment)
    'jaguarmicro'
    '10\.1\.254'
)

# Files to skip (patterns defined here are expected)
SKIP_FILES=(
    'tools/git-secrets-hook.sh'
)

STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)
[ -z "$STAGED_FILES" ] && exit 0

RED='\033[0;31m'
NC='\033[0m'
FAILED=0

while IFS= read -r FILE; do
    for SKIP in "${SKIP_FILES[@]}"; do
        [[ "$FILE" == "$SKIP" ]] && continue 2
    done
    for PAT in "${PATTERNS[@]}"; do
        if git show ":$FILE" 2>/dev/null | grep -qE "$PAT"; then
            echo -e "${RED}[BLOCKED]${NC} $FILE matches: $PAT"
            FAILED=1
        fi
    done
done <<< "$STAGED_FILES"

if [ "$FAILED" -eq 1 ]; then
    echo ""
    echo -e "${RED}Commit blocked: sensitive data detected.${NC}"
    echo "For hook definition update, temporarily use: git commit --no-verify"
    exit 1
fi

exit 0
