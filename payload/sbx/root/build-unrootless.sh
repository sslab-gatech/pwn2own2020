#!/bin/bash
git clone https://github.com/LinusHenze/Unrootless-Kext.git
cd Unrootless-Kext
xcodebuild
cp build/Release/Unrootless.kext/Contents/MacOS/Unrootless ..

