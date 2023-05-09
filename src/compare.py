#A simple program to compare two files. 

import sys

def read_file(file):
    with open(file, 'r', encoding='utf-8', errors='replace') as file:
        content = file.read()
    return content

def compare_files(file1, file2):
    fil1 = read_file(file1)
    fil2 = read_file(file2)
    
    if fil1 == fil2:
        print("The files are identical.")
    else:
        print("The files are different.")

file1 = sys.argv[1]
file2 = sys.argv[2]
compare_files(file1, file2)