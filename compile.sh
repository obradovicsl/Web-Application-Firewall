#!/bin/bash
# Read all from .env
set -a
source .env
set +a

echo "🔨 Compiling RE2 wrappers..."
# Kompajliraj C++ wrapper prvo
g++ -std=c++17 -O2 \
    -I/opt/homebrew/include \
    -Ianalyzer \
    -c analyzer/re2_wrapper.cpp \
    -o analyzer/re2_wrapper.o

# Provjeri da li je wrapper uspješno kompajliran
if [ $? -ne 0 ]; then
    echo "❌ Error while compiling RE2 wrappers!"
    exit 1
fi

echo "🔨 Compiling C modules..."
# Kompajliraj C fajlove
gcc -O2 \
    -I/opt/homebrew/include \
    -Ianalyzer/detectors \
    -Ianalyzer \
    -c analyzer/${C_NAME} \
    -o analyzer/main.o

gcc -O2 \
    -I/opt/homebrew/include \
    -Ianalyzer \
    -c analyzer/html-decoder.c \
    -o analyzer/html-decoder.o

gcc -O2 \
    -I/opt/homebrew/include \
    -Ianalyzer/detectors \
    -Ianalyzer \
    -c analyzer/detectors/detection.c \
    -o analyzer/detectors/detection.o

echo "🔗 Component linking..."
# Final linkovanje sa g++ (jer imaš C++ kod u wrapper-u)
g++ -O2 \
    analyzer/main.o \
    analyzer/html-decoder.o \
    analyzer/detectors/detection.o \
    analyzer/re2_wrapper.o \
    -L/opt/homebrew/lib \
    -lre2 \
    -luri_encode \
    -ljson-c \
    -o ${ANALYZER_NAME}

# Provjeri da li je linkovanje uspješno
if [ $? -eq 0 ]; then
    echo "✅ ${C_NAME} compiled to ${ANALYZER_NAME} and ready for use"
    
    # Očisti privremene object fajlove
    rm -f analyzer/*.o analyzer/detectors/*.o
    
else
    echo "❌ Greška pri linkovanju!"
    exit 1
fi