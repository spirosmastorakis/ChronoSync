#!/usr/bin/env bash
set -x
set -e

sudo rm -Rf /usr/local/include/ChronoSync
sudo rm -f /usr/local/lib/libChronoSync*
sudo rm -f /usr/local/lib/pkgconfig/ChronoSync*

# Cleanup
sudo ./waf -j1 --color=yes distclean

# Configure/build in debug mode
./waf -j1 --color=yes configure --with-tests --debug
./waf -j1 --color=yes build

# Cleanup
sudo ./waf -j1 --color=yes distclean

# Configure/build in optimized mode without tests
./waf -j1 --color=yes configure
./waf -j1 --color=yes build

# Cleanup
sudo ./waf -j1 --color=yes distclean

# Configure/build in optimized mode with tests
./waf -j1 --color=yes configure --with-tests
./waf -j1 --color=yes build

# Install
sudo ./waf install -j1 --color=yes
sudo ldconfig || true
