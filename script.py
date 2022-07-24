#!/user/bin/python
import os
import subprocess
file_name_abs = []
file_name = []
if not (os.path.exists("result")):
	os.mkdir("result")
	print("create file")
for dirpath,_,filenames in os.walk(r"/home/lai/Desktop/peepdf/contagio_Benign2"):
	for f in filenames:
		file_name_abs.append(os.path.abspath(os.path.join(dirpath, f)))
		file_name.append(f)
js_code = ""
for filedir,name in zip(file_name_abs,file_name):
	sc1 = "python2 peepdf.py -l -f -s xtract.txt " + filedir
	os.system(sc1)
	if os.stat("all.pdf").st_size != 0: 
		sc2 = "cp all.pdf result/" + name + ".pdf"
		os.system(sc2)

sc3 = "$ls | tee -a error.txt"
os.system(sc3)
print(" --- end --- ")

