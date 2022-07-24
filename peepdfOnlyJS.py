#!/usr/bin/env python

#
# peepdf is a tool to analyse and modify PDF files
#    http://peepdf.eternal-todo.com
#    By Jose Miguel Esparza <jesparza AT eternal-todo.com>
#
#    Copyright (C) 2011-2017 Jose Miguel Esparza
#
#    This file is part of peepdf.
#
#        peepdf is free software: you can redistribute it and/or modify
#        it under the terms of the GNU General Public License as published by
#        the Free Software Foundation, either version 3 of the License, or
#        (at your option) any later version.
#
#        peepdf is distributed in the hope that it will be useful,
#        but WITHOUT ANY WARRANTY; without even the implied warranty of
#        MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
#        GNU General Public License for more details.
#
#        You should have received a copy of the GNU General Public License
#        along with peepdf.    If not, see <http://www.gnu.org/licenses/>.
#

'''
    Initial script to launch the tool
'''

import sys
import os
import re

from PDFCore import PDFParser

##ret, pdf = pdfParser.parse(fileName, options.isForceMode, options.isLooseMode, options.isManualAnalysis)
VT_KEY = 'fc90df3f5ac749a94a94cb8bf87e05a681a2eb001aef34b6a0084b8c22c97a64'

root = '/home/wasn/wei/peepdf'
OurBenign = '/home/wasn/wei/dataset_split/benign_9109'
OurMalicious = '/home/wasn/wei/dataset_split/malicious_30071'
ZXBenign = '/home/wasn/wei/dataset_split/zx_benign'
ZXMalicious = '/home/wasn/wei/dataset_split/zx_malicious'
allOurBenign = os.listdir(OurBenign)
allOurMalicious = os.listdir(OurMalicious)
allZXBenign = os.listdir(ZXBenign)
allZXMalicious = os.listdir(ZXMalicious)


# print('/////////////////////OurBenign/////////////////')

# JSFolder = 'OurBenignJS'
# if not (os.path.exists(JSFolder)):
# 	os.mkdir(JSFolder)
# 	print("create folder")
# JSFolderPath = os.path.join(root,JSFolder)

# newLine = os.linesep
# JS = 0
# NoJS = 0
# total = ''
# for fileName in allOurBenign:
# 	output = ''
# 	##extractedUrisPerObject = []
# 	extractedJsPerObject = []

# 	try:
# 		pdfParser = PDFParser()
# 		ret, pdf = pdfParser.parse(os.path.join(OurBenign,fileName), True, False, False)

# 		extractedJsPerObject = pdf.getJavascriptCode(None, perObject=True)

# 		for version in range(len(extractedJsPerObject)):
# 			for extractedJs in extractedJsPerObject[version]:
# 				output += '// peepdf comment: Javascript code located in object %d (version %d)%s%s%s' % (extractedJs[0], version, newLine*2, extractedJs[1],newLine*2)
		
# 		if output is not '':
# 			newfilename = os.path.splitext(fileName)[0] + '.txt'
# 			f = open(os.path.join(JSFolderPath,newfilename), 'w')
# 			f.write(output)
# 			f.close()
# 			p = '%-75s %s' % fileName , "Done"
# 			print(p)
# 			total += p
# 			total += '\n'

# 			JS += 1
# 		else: 
# 			p = '%-75s %s' % fileName , "No JS"
# 			print(p)
# 			total += p
# 			total += '\n'
# 			NoJS += 1

# 	except:
# 		print ('%-75s %s') % (fileName , "Have Exception")


# f = open(os.path.join(JSFolderPath,'CountNumber.txt'), 'w')
# content = 'JS = ' + str(JS) + ' , NoJS = ' + str(NoJS)
# f.write(output)
# f.close()

# f = open(os.path.join(JSFolderPath,'Detail.txt'), 'w')
# f.write(total)
# f.close()

#############################################################

print('/////////////////////OurMalicious/////////////////')
JSFolder = 'OurMaliciousJS'
if not (os.path.exists(JSFolder)):
	os.mkdir(JSFolder)
	print("create folder")
JSFolderPath = os.path.join(root,JSFolder)

newLine = os.linesep
JS = 0
NoJS = 0
total = ''
for fileName in allOurMalicious:
	output = ''
	##extractedUrisPerObject = []
	extractedJsPerObject = []

	try:
		pdfParser = PDFParser()
		ret, pdf = pdfParser.parse(os.path.join(OurMalicious,fileName), True, False, False)

		extractedJsPerObject = pdf.getJavascriptCode(None, perObject=True)

		for version in range(len(extractedJsPerObject)):
			for extractedJs in extractedJsPerObject[version]:
				output += '// peepdf comment: Javascript code located in object %d (version %d)%s%s%s' % (extractedJs[0], version, newLine*2, extractedJs[1],newLine*2)
		# print('here')
		if output is not '':
			newfilename = os.path.splitext(fileName)[0] + '.txt'
			# print('here2')
			f = open(os.path.join(JSFolderPath,newfilename), 'w')
			# print('here3')
			f.write(output)
			f.close()
			p = ('%-75s %s') % (fileName , "Done")
			print(p)
			total += p
			total += '\n'

			JS += 1
		else: 
			p = ('%-75s %s') % (fileName , "No JS")
			print(p)
			total += p
			total += '\n'
			NoJS += 1

	except Exception as e:
		print ('%-75s %s') % (fileName , "Have Exception")
		# print (str(e))


f = open(os.path.join(JSFolderPath,'CountNumber.txt'), 'w')
content = 'JS = ' + str(JS) + ' , NoJS = ' + str(NoJS)
f.write(output)
f.close()

f = open(os.path.join(JSFolderPath,'Detail.txt'), 'w')
f.write(total)
f.close()

#############################################################

print('/////////////////////ZXMalicious/////////////////')
JSFolder = 'ZXMaliciousJS'
if not (os.path.exists(JSFolder)):
	os.mkdir(JSFolder)
	print("create folder")
JSFolderPath = os.path.join(root,JSFolder)

newLine = os.linesep
JS = 0
NoJS = 0
total = ''
for fileName in allZXMalicious:
	output = ''
	##extractedUrisPerObject = []
	extractedJsPerObject = []

	try:
		pdfParser = PDFParser()
		ret, pdf = pdfParser.parse(os.path.join(ZXMalicious,fileName), True, False, False)

		extractedJsPerObject = pdf.getJavascriptCode(None, perObject=True)

		for version in range(len(extractedJsPerObject)):
			for extractedJs in extractedJsPerObject[version]:
				output += '// peepdf comment: Javascript code located in object %d (version %d)%s%s%s' % (extractedJs[0], version, newLine*2, extractedJs[1],newLine*2)
		
		if output is not '':
			newfilename = os.path.splitext(fileName)[0] + '.txt'
			f = open(os.path.join(JSFolderPath,newfilename), 'w')
			f.write(output)
			f.close()
			p = ('%-75s %s') % (fileName , "Done")
			print(p)
			total += p
			total += '\n'

			JS += 1
		else: 
			p = ('%-75s %s') % (fileName , "No JS")
			print(p)
			total += p
			total += '\n'
			NoJS += 1

	except:
		print ('%-75s %s') % (fileName , "Have Exception")


f = open(os.path.join(JSFolderPath,'CountNumber.txt'), 'w')
content = 'JS = ' + str(JS) + ' , NoJS = ' + str(NoJS)
f.write(output)
f.close()

f = open(os.path.join(JSFolderPath,'Detail.txt'), 'w')
f.write(total)
f.close()



#############################################################

print('/////////////////////ZXBenign/////////////////')
JSFolder = 'ZXBenignJS'
if not (os.path.exists(JSFolder)):
	os.mkdir(JSFolder)
	print("create folder")
JSFolderPath = os.path.join(root,JSFolder)

newLine = os.linesep
JS = 0
NoJS = 0
total = ''
for fileName in allZXBenign:
	output = ''
	##extractedUrisPerObject = []
	extractedJsPerObject = []

	try:
		pdfParser = PDFParser()
		ret, pdf = pdfParser.parse(os.path.join(ZXBenign,fileName), True, False, False)

		extractedJsPerObject = pdf.getJavascriptCode(None, perObject=True)

		for version in range(len(extractedJsPerObject)):
			for extractedJs in extractedJsPerObject[version]:
				output += '// peepdf comment: Javascript code located in object %d (version %d)%s%s%s' % (extractedJs[0], version, newLine*2, extractedJs[1],newLine*2)
		
		if output is not '':
			newfilename = os.path.splitext(fileName)[0] + '.txt'
			f = open(os.path.join(JSFolderPath,newfilename), 'w')
			f.write(output)
			f.close()
			p = ('%-75s %s') % (fileName , "Done")
			print(p)
			total += p
			total += '\n'

			JS += 1
		else: 
			p = ('%-75s %s') % (fileName , "No JS")
			print(p)
			total += p
			total += '\n'
			NoJS += 1

	except:
		print ('%-75s %s') % (fileName , "Have Exception")


f = open(os.path.join(JSFolderPath,'CountNumber.txt'), 'w')
content = 'JS = ' + str(JS) + ' , NoJS = ' + str(NoJS)
f.write(output)
f.close()

f = open(os.path.join(JSFolderPath,'Detail.txt'), 'w')
f.write(total)
f.close()

