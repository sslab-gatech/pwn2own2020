#!/usr/bin/env python3
import os
import subprocess

with open('payload/sbx/sbx', 'rb') as f:
    stage2 = f.read()

with open('payload/loader/loader.bin', 'rb') as f:
    stage1 = f.read()

with open('stage0.bin', 'rb') as f:
    stage0 = f.read()

def js_repr(_b):
    return ', '.join(map(hex, map(int, _b)))

output = '''
const stage0 = [
    %s
];
const stage1 = [
    %s
];
const stage2 = [
    %s
];

stage1Arr = new Uint8Array(stage1);
stage2Arr = new Uint8Array(stage2);
''' % (
    js_repr(stage0),
    js_repr(stage1),
    js_repr(stage2),
)
output = output[1:]

with open('payload.js', 'w') as f:
    f.write(output)
