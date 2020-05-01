# !/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import angr
import capstone
import claripy
from tools.image import Image
from tools.util.asm import is_jump
import redis

def cal_incoming_calls(path):
    """calculate the incoming calls of a binary program"""
    r = redis.Redis(host='localhost', port=6379, db=1)
    r.flushdb()
    img = Image(path)
    # every function is counted once
    funcs = img.funcs
    for func in funcs:
        cfg = img.get_cfg(func)
        cfg.normalize()
        callgraph = cfg.functions.callgraph
        for addr in list(callgraph):
            if r.exists(addr):
                r.set(addr, int(r.get(addr)+1))
            else:
                r.set(addr, 1)
    r.save()


if __name__ == "__main__":
    debug_vmlinux = "../testcase/2423496af35d94a87156b063ea5cedffc10a70a1/vmlinux"
    cal_incoming_calls(debug_vmlinux)
