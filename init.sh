#!/bin/bash

set -e

echo "Cloning noise-c..."
git clone https://github.com/rweather/noise-c || { echo "Error: failed to clone noise-c"; exit 1; }

cd noise-c
echo "Running autoreconf..."
autoreconf -i || { echo "Error: autoreconf failed"; exit 1; }

mkdir build
cd build
echo "Configuring build..."
../configure --prefix="$HOME/.local" || { echo "Error: configure failed"; exit 1; }

echo "Building noise-c..."
make || { echo "Error: make failed"; exit 1; }

echo "Installing noise-c to $HOME/.local..."
make install || { echo "Error: make install failed"; exit 1; }

cd ../../
mkdir -p build
cp -r "$HOME/.local/"* ./build/

echo "Cleaning noise-c..."
rm -rf noise-c/

echo "Cloning cJSON..."
git clone https://github.com/DaveGamble/cJSON || { echo "Error: failed to clone cJSON"; exit 1; }

# Rename to avoid case-insensitive conflict (on macOS)
mv cJSON cJSON_tmp

echo "Copying cJSON sources to ./cjson..."
mkdir -p cjson
cp cJSON_tmp/cJSON.c ./cjson/
cp cJSON_tmp/cJSON.h ./cjson/

echo "Cleaning cJSON..."
rm -rf cJSON_tmp

echo "[✓] All steps completed successfully."