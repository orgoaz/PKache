#!/usr/bin/env python


import math
lines = []
for i in range(1, 100):
    s = '{}: set_val({}),\n'.format(i, int(round(math.log(i, 2) * 100)))
    lines.append(s)

with open('match_action_table.p4', 'w') as f:
    f.writelines(lines)