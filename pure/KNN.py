#!/home/xianglin/.virtualenvs/angr/bin/ python
# -*- coding: utf-8 -*-
__Auther__ = 'xianglin'

import pyflann
import numpy as np
import pandas as pd


def get_data(path):
    """
    get the data from database

    Args:
        the path to target csv file

    Returns:
        dataset_numeric(ndarray): the numeric features of functions from database
        dataset_labels(ndarray): the corresponding binary name and function name
    """

    df = pd.read_csv(path)
    data = df.to_numpy()
    numerics = data[:, 2:].astype('int32')
    labels = data[:, 0:2]
    return numerics, labels


def get_label_name(label):
    """get label name from a list to a str"""
    return ','.join(label)

def numeric_filter(dataset_path, testset_path, sim_num=16):
    """
    find the top sim_num similar functions in the database compare to test data

    Args:
        dataset_path(str): the path to dataset csv
        testset_path(str): the path to testset csv
        sim_num: the number of similar functions that you want to get from dataset

    Returns:
        ans(dict): a dict mapping from test funcion to its similar functions in the database
        for example:
            {[bin_name,func_name]:[[bin1,func1],[bin2, func2],[bin3, func3]]}
    """
    dataset_numeric, dataset_labels = get_data(dataset_path)
    testset_numeric, testset_labels = get_data(testset_path)

    flann = pyflann.FLANN()
    result, dist = flann.nn(dataset_numeric, testset_numeric, sim_num, algorithm="kdtree", trees=4)

    ans = {}
    for i in range(len(result)):
        key = get_label_name(testset_labels[i].tolist())
        values = list()
        for j in range(sim_num):
            values.append(dataset_labels[result[i][j]].tolist())
        ans[key] = values

    return ans


if __name__ == "__main__":
    path1 = "/home/xianglin/PycharmProjects/discovRE/pure/bin_features/bin_features_2020-05-01-23_54_45.csv"
    path2 = "/home/xianglin/PycharmProjects/discovRE/pure/bin_features/bin_features_2020-05-01-23_51_25.csv"
    ans = numeric_filter(path1, path2)
    print(1)


