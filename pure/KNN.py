#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import pyflann
import numpy as np

dataset = np.array(
    [[1., 1, 1, 2, 3],
     [10, 10, 10, 3, 2],
     [100, 100, 2, 30, 1]
     ])
testset = np.array(
    [[1., 1, 1, 1, 1],
    [100, 100, 2, 3, 1]
     ])
flann = pyflann.FLANN()
result, dists = flann.nn(dataset, testset, 128, algorithm="kdtree", trees=4)


