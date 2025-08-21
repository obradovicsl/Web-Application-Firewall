#!/bin/bash
# Read all from .env
set -a
source .env
set +a

echo "🔨 Kompajliranje RE2 wrapper-a..."
# Kompajliraj C++ wrapper prvo
g++ -std=c++17 -O2 \
    -I/opt/homebrew/include \
    -Ianalyzer \
    -c analyzer/re2_wrapper.cpp \
    -o analyzer/re2_wrapper.o

# Provjeri da li je wrapper uspješno kompajliran
if [ $? -ne 0 ]; then
    echo "❌ Greška pri kompajliranju RE2 wrapper-a!"
    exit 1
fi

echo "🔨 Kompajliranje C modula..."
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
    -c analyzer/detectors/sqli_detection.c \
    -o analyzer/detectors/sqli_detection.o

gcc -O2 \
    -I/opt/homebrew/include \
    -Ianalyzer/detectors \
    -Ianalyzer \
    -c analyzer/detectors/xss_detection.c \
    -o analyzer/detectors/xss_detection.o

echo "🔗 Linkovanje svih komponenti..."
# Final linkovanje sa g++ (jer imaš C++ kod u wrapper-u)
g++ -O2 \
    analyzer/main.o \
    analyzer/html-decoder.o \
    analyzer/detectors/sqli_detection.o \
    analyzer/detectors/xss_detection.o \
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