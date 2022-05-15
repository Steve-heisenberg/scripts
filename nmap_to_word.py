# Welcome function
def msg():
	print('''
###################################################
# Tool    : nmap_to_word                          #
# Coded with Python 3.7.5                         #
# Procedure:                                      #
# 	Choice 1) Give list of files one by one / #
#	   comma separated to retrieve open ports #
#	Choice 2) Give folder path which has the  #
#	   files to be converted		  #
# Author  : Anitha             		          #
# Tested in : Linux & Windows 		          #
###################################################
	''')

try:
	from docx import Document
except:
	print('''
	Need to install python-docx
	Run commands: pip3 install python-docx
	''')

# Required imports
import sys
import os
import re

def extract_open_ports(filename, content):
	# pattern to match the open ports 
	pattern_tcp = re.compile('\d+\/tcp\s+open\s+')
	pattern_udp = re.compile('\d+\/udp\s+open\s+')
	if os.path.isfile(filename):
		with open("open_ports.txt", "a") as f:
			f.write('\n'+filename)
			for line in content:				
				# Checking for new IP
				if line.startswith("Nmap scan report for "):
					ip = line.split(" ")[-1].strip("\n")
					if ip[0] == '(' and ip[-1] == ')':
						ip = ip[1:-1]
					f.write('\n\n'+ip+'\n')
				#retrieving open TCP/UDP ports and writing into "open_ports.txt" file with proper formatting
				elif pattern_tcp.match(line) or pattern_udp.match(line):
					line = ''.join(' '.join(line.split()).split()[0:3])
					line = line.replace('open','')
					line = line.replace('?','')
					if(line[2] == "/"):
						line = line.replace('/tcp','/TCP\t\t')
						line = line.replace('/udp','/UDP\t\t')
					else:
						line = line.replace('/tcp','/TCP\t')
						line = line.replace('/udp','/UDP\t')
					line = line.replace('unknown','-')
					line = line.replace('tcpwrapped','-')
					line = line.replace('ssl/-','ssl/unknown')
					f.write(line+'\n')
			f.close()
	else:
		print("No such file exists.")

def convert():
	d = {} #dictionary to combine the open TCP and UDP ports with the IP
	if os.path.isfile("open_ports.txt"):
		with open("open_ports.txt", "r") as f:
			open_ports = f.readlines()
		f.close()
		#converting the open ports as per IP into a dictionary
		ip_pattern = re.compile('^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$')

		for line in open_ports:
			if ip_pattern.match(line) and '.txt' not in line:
				ip = line.strip('\n')
				if ip in d:
					pass
				else:
					d[ip] = ''
			elif line == '\n' or '.txt' in line or line == '':
				pass
			else:
				d[ip] += line
		#print(d)
		
		document = Document()
		# add table ------------------
		table = document.add_table(1, 3, style='TableGrid')

		# populate header row --------
		heading_cells = table.rows[0].cells
		heading_cells[0].text = '#'
		heading_cells[1].text = 'IP Address'
		heading_cells[2].text = 'Ports'

		# add a data row for each IP
		x = 0
		for key, value in d.items():
			cells = table.add_row().cells
			cells[0].text = str(x+1)
			cells[1].text = key
			if value == '':
				cells[2].text = '-'
			else:
				cells[2].text = value[0:-1]
			x += 1

		if os.path.exists('Port_Listing.docx'):
			f = input("Port_Listing.docx file already exists!!!\nEnter new document name (without docx extension): \n")
			document.save(f+'.docx')
		else:
			document.save('Port_Listing.docx')
		os.remove("open_ports.txt")

	else:
		print("'open_ports.txt' file does not exists.")

if __name__=='__main__':
	msg() # Welcome message
	
	if os.path.isfile("open_ports.txt"):
		os.remove("open_ports.txt")
	open("open_ports.txt", 'a').close()

	while True:
		print("1) File wise\n2) Folder wise\n3) Quit\nEnter ur choice:")

		ch = int(input())
		if ch == 1:
			# Reading nmap output (.txt file)
			while True:
				filenames = input("Enter filenames (one by one / comma separated) or 'q' to quit: \n").split(",")
				if len(filenames) == 1 and filenames[0] == "q":
					#output_file = input("Enter doc filename (without .docx extension): \n")
					convert()
					sys.exit()
				for i in range(len(filenames)):
					if filenames[i].endswith('.txt'):
						pass
					else:
						filenames[i]=filenames[i]+'.txt'
				#print(filenames)
				for i in range(len(filenames)):
					#print(filenames[i])
					if os.path.isfile(filenames[i]):
						try:
							with open(filenames[i], "r") as f:
								content = f.readlines()
								extract_open_ports(filenames[i], content)
							f.close()
						except:
							print("No such file exists. Please enter filename (.txt) again")
					else:
						print ("File", filenames[i], "not exists")

		elif ch == 2:
			while True:
				path = input("Enter folder path or 'q' to quit: \n")
				if len(path) == 1 and path == "q":
					#output_file = input("Enter doc filename (without .docx extension): \n")
					convert()
					sys.exit()
				files = os.scandir(path)
				for file in files:
					if os.path.isfile(path+"/"+file.name):
						try:
							with open(path+"/"+file.name, "r") as f:
								content = f.readlines()
								extract_open_ports(path+"/"+file.name, content)
							f.close()
						except:
							print("No such file exists. Please enter filename (.txt) again")
					else:
						print ("File", path+"/"+file.name, "not exists")
		else:
			os.remove("open_ports.txt")
			sys.exit()
