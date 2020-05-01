#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import angr
import capstone
import claripy
from tools.image import Image
from tools.util.asm import is_jump
import NumericFeatureExtractor
import numpy as np
from collections import Counter


def jaccard_similarity(a, b):
    if len(a) == 0 and len(b) == 0:
        return 1.0
    if len(a) == 0 or len(b) == 0:
        return 0.0
    _a = Counter(a)
    _b = Counter(b)
    c = (_a - _b) + (_b - _a)
    intersection = (len(a) + len(b) - sum(c.values())) / 2
    similarity = intersection / (len(a) + len(b) - intersection)
    return similarity


def jaccard_distance(a, b):
    """
    calculate the distance between two consts list, jaccard distance is set to be 1 - jaccard similarity
    Args:
        a(list): a list of string consts
        b(list)
    Returns:
        distance(float)
    """
    similarity  = jaccard_similarity(a, b)
    distance = 1 - similarity
    return distance


def get_feaV(img, block):
    """get feature vector from a basic block"""
    string_consts, num_consts = NumericFeatureExtractor.get_BB_consts(img, block)
    calls = NumericFeatureExtractor.cal_call_insts(block)
    logics = NumericFeatureExtractor.cal_logic_insts(block)
    transfers = NumericFeatureExtractor.cal_transfer_insts(block)
    instrs = NumericFeatureExtractor.cal_insts(block)
    arithmetics = NumericFeatureExtractor.cal_arithmetic_insts(block)

    feature_vec = list()
    feature_vec.append(string_consts)
    feature_vec.append(num_consts)
    feature_vec.append(arithmetics)
    feature_vec.append(calls)
    feature_vec.append(instrs)
    feature_vec.append(logics)
    feature_vec.append(transfers)

    return feature_vec


def BB_distance(v1, v2):
    # string constants, numeric constants, arithmetic, calls, instr, logic, transfer
    alpha = np.array([11.998, 15.382, 56.685, 87.423, 40.423, 76.694, 6.841])
    max_a = np.hstack((np.array([1.0, 1.0]), np.maximum(v1[2:], v2[2:])))
    str_d = jaccard_distance(v1[0], v2[0])
    num_d = jaccard_distance(v1[1], v2[1])
    distance_a = np.hstack((np.array([str_d, num_d]), np.abs(np.array(v1[2:]) - np.array(v2[2:]))))
    distance = np.sum(np.multiply(alpha, distance_a)) / np.sum(np.multiply(alpha, max_a))
    return distance



