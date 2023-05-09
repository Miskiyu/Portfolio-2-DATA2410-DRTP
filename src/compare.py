#A simple program to compare two files, made entierly by chatGPT

import sys

def read_file(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='replace') as file:
        content = file.read()
    return content

def compare_files(file1, file2):
    content1 = read_file(file1)
    content2 = read_file(file2)
    
    if content1 == content2:
        print("The files are identical.")
    else:
        print("The files are different.")

file1 = sys.argv[1]
file2 = sys.argv[2]
compare_files(file1, file2)