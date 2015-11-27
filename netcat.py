
#coding:utf-8
"""
  Author: Arche  --<>
  Purpose: 
  Created: 2015/11/25
"""

import socket
import subprocess
import getopt
import sys
import threading
import os
import platform

target = "0.0.0.0"  #ip 当作为服务端时，设置为本地地址。客户端时，设置为要连接的远程地址
port = 9999  #端口
listen = False  #是否监听，当为监听模式，则为服务器端
command = False  #是否shell模式.
execute = ""
upload = ""  #是否为文件上传模式,其值为文件要上传的地址 如c:\\windows\\system32\\cmd.exe

DEBUG = False

def usage():
    print 'Usage:'
    print '\tpython %s -t 192.168.0.102 -p 9999 -l -c' %(__file__) #提供shell模式的服务端
    print '\tpython %s -t 192.168.0.102 -p 9999 -l -u "c:\\windows\\system32\\cmd.exe"' %(__file__) #上传文件模式的服务端
    print '\tpython %s -t 192.168.0.102 -p 9999' %(__file__) #客户端连接服务器
    print '\techo "ABCDE" | python %s -t 192.168.0.102 -p 9999' %(__file__) #标准输入流的方式给服务器发送字符
    print '\n'




def get_opt():  #解析命令行参数
    global target
    global port
    global listen
    global command
    global upload
    global execute
    try:
        options,args = getopt.getopt(sys.argv[1:],"hlce:t:p:u:",["help","listen","command","execute=","target=","port=","upload="])
        for o,a in options:
            if o in ("-h","--help"):
                usage()
                sys.exit(0)
                
            if o in ("-l","--listen"):
                listen = True
            if o in ("-c","--command"):
                command = True
            if o in ("-t","--target"):
                target = a
            if o in ("-p","--port"):
                port = int(a)
            if o in ("-u","--upload"):
		upload = a
	    if o in ("-e","--execute"):
		execute = a
                
    except getopt.GetoptError:
        usage()
        sys.exit(0)

def client_sender(data):
    #客户端
    global target
    global port
    global DEBUG
    client = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    data = data.rstrip()
    try:
	print "[*] connect to %s:%s" %(target,port)
	client.connect((target,port))
	
	if not DEBUG:
	    name = raw_input("username: ")
	    passwd = raw_input("password: ")
	    client.send(passwd+"@"+name)
	    response = client.recv(1024)
	    if response != "200":
		print "username or password incorrect"
		return
	
	
	if upload: #上传文件模式 
	    data = ""
	    with open(upload,"rb") as fout:
		for data_buffer in fout:
		    data += data_buffer
	    sender_model(client,data)	
	    
	elif len(data) and data == "shell": #命令行shell模式
	    shell_model(client)
	    
	elif len(data): #发送数据、发送命令模式
	    sender_model(client,data+"\n")

    except :
	print "[*] Exception! Exiting."
	client.close()

def shell_model(client):
    global DEBUG
    #命令行shell模式---客户端交互
    print "[*] Shell Model"
    shell_pre = client.recv(1024) #连接成功  服务器返回前缀 如：127.0.0.1@shell#
    while True:
	recv_len = 1
	response = ""
	buffer = raw_input(shell_pre)
	buffer += "\n"
	if DEBUG:
	    print "[*DEBUG: ] input cmd is " + buffer
	client.send(buffer)			

	while recv_len:
	    data_buffer = client.recv(4096)
	    recv_len = len(data_buffer)
	    if DEBUG:
		print "[*DEBUG: ] shell model recv buffer " + data_buffer
		print "[*DEBUG: ] shell model recv len " , recv_len
	    
	    if data_buffer == "exit ok": #退出shell,断开连接
		print "[*] Exiting ..."
		client.close()
		sys.exit(0)		    
	    #response += data_buffer
	    print data_buffer
	    if recv_len < 4096:
		break
	#print 内容过多时 产生分页加载 不采用一次性print所有结果
	#if response == "exit ok": #退出shell,断开连接
	    #print "[*] Exiting ..."
	    #client.close()
	    #sys.exit(0)		
	#if not DEBUG:
	    #print response   
    
def sender_model(client,data):
    global DEBUG
    #发送数据、命令模式---客户端交互
    print "[*] Data sender or Command sender Model"
    response = client.recv(1024) #连接成功
    if DEBUG:
	print "[*DEBUG: ] sender model connect response is " + response
    print response
    client.send(data)
    response = ""
    while True:
	data_buffer = client.recv(1024)
	if DEBUG:
	    print "[*DEBUG: ]" + data_buffer
	response += data_buffer	
	if len(data_buffer) < 1024:
	    break

    print response    
    
def server_loop():
    #服务器
    global target
    global port
    global DEBUG

    if not len(target):
	target = "0.0.0.0"
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    server.bind((target,port))
    server.listen(5)
    print "[*] Start Server succeed.IP is %s ,Port is %s" %(target,port)

    while True:
	client_socket,(addr,_) = server.accept()
	print "[*] A client connect succeed.IP  is ",addr
	client_thread = threading.Thread(target=client_handler,args=(client_socket,addr))
	client_thread.start()


def run_command(command):
    command = command.rstrip()
    if command == "ls" and 'Win' in platform.system(): #短路原则 将ls判断放前面
	command = "dir"
    try:
	if command.startswith("cd"):
	    cd_dir = command.split(" ")
	    os.chdir(cd_dir[1])
	    output = cd_dir[1]	    
	else:
	    output = subprocess.check_output(command,stderr=subprocess.STDOUT,shell=True)
    except :
	output = "Failed to execute command.\r\n"
    return output

def client_handler(client_socket,addr):
    global upload
    global execute
    global command
    global DEBUG
    
    if not DEBUG:
	user = client_socket.recv(1024)
	if user == "778546@arche":
	    client_socket.send("200")
	else:
	    client_socket.send("-1")
	    return
    

    if len(upload):
	print "[*] Upload path is %s" %upload
	client_socket.send("Uploading...")
	file_buffer = ""
	while True:
	    data = client_socket.recv(1024)
	    file_buffer += data
	    if len(data) < 1024:
		break
	print "[*] Upload content: %s" %file_buffer
	try:
	    file_descriptor = open(upload,"wb")
	    file_descriptor.write(file_buffer)
	    file_descriptor.close()

	    client_socket.send("Successfully saved file to %s \r\n" %upload)
	except:
	    client_socket.send("Failed to save file to %s \r\n" %upload)
    if len(execute):
	output = run_command(execute)
	client_socket.send(output)

    if command:
	try:
	    client_socket.send(addr+"@shell# ") #连接成功
	    while True:
		cmd_buffer = ""
		while "\n" not in cmd_buffer:
		    cmd_buffer += client_socket.recv(1024)
		cmd_buffer = cmd_buffer.rstrip()
		print "[*] cmd:" + cmd_buffer
		if cmd_buffer == "exit" or cmd_buffer == "quit":
		    client_socket.send("exit ok")
		    client_socket.close()
		    print "[*] IP %s is disconnected" %addr
		    break
		    
		response = run_command(cmd_buffer)
		client_socket.send(response if len(response) > 0 else " ")
	except :
	    print "[*] IP %s is disconnected" %addr
	    client_socket.close()
	



        
if __name__ == '__main__':
    if not len(sys.argv[1:]):
        usage()
        sys.exit(0)
    
    get_opt()
    
    if not listen and len(target) and port > 0:
	print "input 'shell' to into the shell model or input data or command code to send"
     	buffer = sys.stdin.readline()
	#if buffer.find("\n"):
	client_sender(buffer)
    if listen:
     	server_loop()

        