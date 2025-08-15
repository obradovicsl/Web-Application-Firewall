set -a
source .env
set +a

gcc -O2 -I/opt/homebrew/include -L/opt/homebrew/lib -ljson-c -o ${ANALYZER_NAME} analyzer.c