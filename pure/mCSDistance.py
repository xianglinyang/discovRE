#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import angr
import capstone
import claripy
from tools.image import Image
from tools.util.asm import is_jump
import redis
import pandas as pd
import csv
import time
import CalIncomingCalls
import os


'''the output from knn.py would give the bin_name and function name of the target function'''
bin1 = ''
func1 = ''
bin2 = ''
func2 = ''


def get_func_cdg(bin, func):
    pass


def get_mcs(g1, g2):
    pass


def get_func_dist(g1, g2):
    pass
