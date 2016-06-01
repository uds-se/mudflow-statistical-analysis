#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
extract and convert valuable data from orca output

This script is used to parse Orca huge plain output into more compact data
as well as to exchande row ids to app names 
<feature_amount> (default value = 5) most important features are filtered

Orca doesn't preserve row_id <-> row_name binding, it should be done manually
So 2d argument should point to the file that was analised!
by that reason for now neigbours printing doesn't work! when outliers are inspected

Arguments:
1st - orca output (one particular cluster); should include cluster number
2d  - file, containing row names (made by orca_prepare script); this file is the input for orca
3d  - resulting output file - read-friendly format
4th - resulting csv file, collecting all outliers (throughout all clusters)
"""

import sys
import re
import csv
import os

#RECORD_PATTERN = "Record:"
feature_amount = 10 # number of selected main features
print_neighbours = False # whether to print nearest neighbours (in terms of distance)
                         # should be false! if test and base sets in orca input are different
                         #FIXIT

def parse_rec(line):
    m = re.match(".*Record:\s*(\d*)\s*Score:\s*([\d\\.\\+e]*)", line)
    if m==None:
        print line
    row_num = m.group(1)
    score = m.group(2)
    return int(row_num), float(score)

def parse_neighb(line):
    m = re.match("\s*Neighbors:\s+([\d\s]+)", line)
    if (m==None):
        m = re.match("\s*([\d\s]+)",line)
    l = m.group(1)
    neighbors = l.split()
    return neighbors

def parse_feature(line):
    m = re.match(".*:\s+([\d\\.]+)", line)
    if (m == None):
        return None
    score = float(m.group(1))
    if (score>0):
        return m.group(0)
    return 0 #return zero score

def get_meta(meta, idx):
    line = meta[idx - 1]
    m = line.split(",")
    return m[0]

def get_cluster(filename):
    res = re.search("([A-Z_]+)", os.path.split(filename)[1])
    return res.group(0)

def main():

## for debug only
    if (len(sys.argv)>1) and (sys.argv[1]):
        datafile = sys.argv[1]
    else:
        datafile = '/home/konst/LAB/orca/data/cluster-1.txt'
    
    if (len(sys.argv)>2) and (sys.argv[2]):
        metafile = sys.argv[2]
    else:
        metafile = '/home/konst/LAB/orca/data/chabada-1.data'

    if (len(sys.argv)>3) and (sys.argv[3]):
        resfile = sys.argv[3]
    else:
        resfile = '/home/konst/LAB/orca/data/report-1.txt'

    if (len(sys.argv)>4) and (sys.argv[4]):
        csvfilename = sys.argv[4]
    else:
        csvfilename = '/home/konst/LAB/orca/data/report.csv'
##
    path, name = os.path.split(datafile)
    print datafile
    #f_name, f_extension = os.path.splitext(datafile)
    backdatafile = path + "/allwide-" + name
    cluster_num = get_cluster(datafile)

    with open(datafile, "r") as data, open(backdatafile, "w") as backdata, open(metafile, "r") as meta, open(resfile, "w") as res, open(csvfilename, 'a') as csvfile:
        metadata = meta.readlines()
        csv_writer = csv.writer(csvfile, delimiter=';')
        header = True
        capture_feature = False
        try:
            while (True):
                line = data.next()
                if (header):
                    if "Top outliers:" in line:
                        header = False
                    else:
                        backdata.write(line)
                if " Record:" in line:
                    backdata.write(line)
                    row_num, score = parse_rec(line)
                    name = get_meta(metadata, row_num)
                    res.write("Outlier name: {} Score: {} \n".format(name, score))
                    csv_row = [name, cluster_num, score]
                    csv_writer.writerow(csv_row)
                    line = data.next()
                    backdata.write(line)
                    if (False):
			    while ("feature importance:" not in line):
		                if print_neighbours:
		                    neighb = parse_neighb(line)
		                    res.write("Closest neighbours:\n")
		                    for item in neighb:
		                        name = get_meta(metadata, int(item))
		                        res.write("name: {}\n".format(name))
		                line = data.next()
		                backdata.write(line)
		            res.write("Feature importance:\n")
		            capture_feature = True
                    feature_counter = 0
                elif capture_feature:
                    feature = parse_feature(line)
                    if feature == None:
                        capture_feature = False
                        res.write("\n")
                        backdata.write(line)
                        continue
                    if feature == 0:
                        continue
                    backdata.write(line)
                    feature_counter += 1
                    if feature_counter <= feature_amount:
                        res.write(line)
        except StopIteration as e:
            data.close()
            meta.close()
            res.close()
            csvfile.close()
            os.remove(datafile)
            os.rename(backdatafile,datafile)

if __name__ == "__main__":
    main()
