#!/usr/bin/env python
#coding:utf-8
# 一些凌乱的小函数
#from config import config

import sys
import os
def prefork(forklen):
    if sys.platform.find("lin") == -1:
        return False
    for i in range(forklen):
        os.fork()
    return True
