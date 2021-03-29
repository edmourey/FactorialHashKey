# This file is dual licensed under the terms of the Apache License, Version
# 2.0, and the BSD License. See the LICENSE file in the root of this repository
# for complete details.

# calculate key teeth
import math

for i in range(1, 33):
    key_size = 2 ** (i * 8)
    teeth = 1
    while True:
        if math.factorial(teeth) < key_size:
            teeth += 1
        else:
            break
    print(str(i*8) + ":", str(teeth)+ ",")

