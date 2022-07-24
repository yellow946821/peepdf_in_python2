#!/user/bin/python
import os
import subprocess
file_name_abs = []
file_name = []

for dirpath,_,filenames in os.walk(r"//home/lai/Desktop/peepdf/contagio_Benign"):
	n = 1
	for f in filenames:
		os.rename(os.path.abspath(os.path.join(dirpath, f)) , os.path.abspath(os.path.join(dirpath, str(n))))
		n += 1

