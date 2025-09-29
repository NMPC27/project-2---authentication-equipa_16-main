from tkinter import *
from tkinter import ttk
import socket
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import json
import hashlib
import os

from e_chap import *

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

#DEFINE
CHEKED_BOX = "\u2612"
UNCHEKED_BOX = "\u2610"
MASTER_FILE_KEY = b'\xc9\x96UK\xf6\xecG\xf0l\x02\xa6\xd7Z\xe7\x0ci\xab\xe2N\x16\xd6\xddn\x1d\xf0\xba\x92\xe4\xa1\xa4\xc6H'
MASTER_FILE_IV = b'.\xc8\xe5^l\xf0\xa4\x8b\xce?"\xb5\x15\xf3\x14\x05'

MASTER_USERS_PASS_KEY = "bS5W2+$mGf2V-UE2?,6q*9%t{/ez" #28 -> 4 para o user
MASTER_USERS_IV_KEY = "Y!v:7b{*ey&=" #12 -> 4 para o user

class UAP_Data:
	def __init__(self, DATA,USER):
		self.DATA = DATA
		self.USER = USER

	# ! encriptação simetrica com salt da key e iv e pass
	# ! key e iv sao iguas para o mesmo user
	# ! o salt das pass muda mesmo no mesmo user
def simetric_encript(id,user,password):
	key=MASTER_USERS_PASS_KEY+user[0:4]
	iv=user[0:4]+MASTER_USERS_IV_KEY
	
	salt=str(id)
	result = hashlib.sha256(salt.encode())
	salt=result.hexdigest()

	password=password+salt

	n = 32
	chunks = [password[i:i+n] for i in range(0, len(password), n)]

	while len(chunks[-1])!=32:
		chunks[-1]+=" "

	cipher = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
	encryptor = cipher.encryptor()

	ct=encryptor.update(chunks[0].encode())
	for i in range(1,len(chunks)):
		ct+= encryptor.update(chunks[i].encode())
	
	ct+=encryptor.finalize()

	return list(ct)
	
def simetric_decript(id,user,ct):
	ct=bytes(ct)

	key=MASTER_USERS_PASS_KEY+user[0:4]
	iv=user[0:4]+MASTER_USERS_IV_KEY
	cipher2 = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
	decryptor = cipher2.decryptor()

	salt=str(id)
	result = hashlib.sha256(salt.encode())
	salt=result.hexdigest()

	n = 32
	chunks = [ct[i:i+n] for i in range(0, len(ct), n)]

	dt=decryptor.update(chunks[0])
	for i in range(1,len(chunks)):
		dt+= decryptor.update(chunks[i])
	
	dt+=decryptor.finalize()

	passwrd=dt.decode()
	idx=passwrd.index(salt)
	passwrd=passwrd[0:idx]

	return passwrd


def Click_add_ok(pop_add,site_input,user_input_add,pass_input_add,user,table,*event):
	id=0
	for i in DATA.DATA[user]:# ver id max
		if id<i["id"]:
			id=i["id"]
	id+=1
	
	passwrd=simetric_encript(id,user,pass_input_add.get())
	
	DATA.DATA[user].append({
		"id":id,
		"pass":passwrd,
		"site":site_input.get(),
		"user":user_input_add.get()
	})

	table.insert(parent='', index="end", iid=id, text='', values=(id,site_input.get(),user_input_add.get(),"********",UNCHEKED_BOX))

	pop_add.destroy()


def Click_add(user,table):
	pop_add= Toplevel(GUI)
	pop_add.geometry("300x200+840+440")
	pop_add.title("Add Login")

	site_title = Label(pop_add, text="Site",font=("Arial", 12))
	site_title.place(x=18,y=20)
	site_input = Entry(pop_add, width=35)
	site_input.place(x=60,y=20,height=20)

	user_title_add = Label(pop_add, text="User",font=("Arial", 12))
	user_title_add.place(x=18,y=60)
	user_input_add = Entry(pop_add, width=35)
	user_input_add.place(x=60,y=60,height=20)

	pass_title_add = Label(pop_add, text="Pass",font=("Arial", 12))
	pass_title_add.place(x=18,y=100)
	pass_input_add = Entry(pop_add, width=35)
	pass_input_add.place(x=60,y=100,height=20)

	btn_pop_ok = Button(pop_add,text = "Add",command = lambda: Click_add_ok(pop_add,site_input,user_input_add,pass_input_add,user,table))
	btn_pop_ok.place(x=110,y=150)
	btn_pop_cancel = Button(pop_add,text = "Cancel",command = lambda: pop_add.destroy())
	btn_pop_cancel.place(x=150,y=150)

	pop_add.bind('<Return>', lambda event: Click_add_ok(pop_add,site_input,user_input_add,pass_input_add,user,table))
	

def Click_edit_ok(pop_add,site_input,user_input_add,pass_input_add,user,table,id,selected,*event):
	
	passwrd=simetric_encript(id,user,pass_input_add.get())

	for i in DATA.DATA[user]:
		if i["id"]==int(id):
			i["pass"]=passwrd
			i["site"]=site_input.get()
			i["user"]=user_input_add.get()

	table.item(selected, text="", values=(id,site_input.get(),user_input_add.get(),"********",UNCHEKED_BOX))

	pop_add.destroy()


def Click_edit(table,user,*event):

	selected = table.focus()
	temp = table.item(selected, 'values')

	if temp=="":
		PopUp("Selecione alguma \n coisa!")
		return None

	d_user=None
	d_site=None
	d_pass=None
	for i in DATA.DATA[user]:
		if i["id"]==int(temp[0]):
			d_user=i["user"]
			d_site=i["site"]
			d_pass=i["pass"]
			break


	d_pass=simetric_decript(int(temp[0]),user,d_pass)

	pop_add= Toplevel(GUI)
	pop_add.geometry("300x200+840+440")
	pop_add.title("Edit Login")

	site_title = Label(pop_add, text="Site",font=("Arial", 12))
	site_title.place(x=18,y=20)
	site_input = Entry(pop_add, width=35)
	site_input.insert(0,d_site)
	site_input.place(x=60,y=20,height=20)

	user_title_add = Label(pop_add, text="User",font=("Arial", 12))
	user_title_add.place(x=18,y=60)
	user_input_add = Entry(pop_add, width=35)
	user_input_add.insert(0,d_user)
	user_input_add.place(x=60,y=60,height=20)

	pass_title_add = Label(pop_add, text="Pass",font=("Arial", 12))
	pass_title_add.place(x=18,y=100)
	pass_input_add = Entry(pop_add, width=35)
	pass_input_add.insert(0,d_pass)
	pass_input_add.place(x=60,y=100,height=20)

	btn_pop_ok = Button(pop_add,text = "Edit",command = lambda: Click_edit_ok(pop_add,site_input,user_input_add,pass_input_add,user,table,temp[0],selected))
	btn_pop_ok.place(x=110,y=150)
	btn_pop_cancel = Button(pop_add,text = "Cancel",command = lambda: pop_add.destroy())
	btn_pop_cancel.place(x=150,y=150)

	pop_add.bind('<Return>', lambda event: Click_edit_ok(pop_add,site_input,user_input_add,pass_input_add,user,table,temp[0],selected))


def Click_del(table,user,*event):
	selected = table.focus()
	temp = table.item(selected, 'values')

	if temp=="":
		PopUp("Selecione alguma \n coisa!")
	else:
		for i in DATA.DATA[user]:
			if i["id"]==int(temp[0]):
				DATA.DATA[user].remove(i)
				break

		table.delete(selected)


def Click_logout(table,btn_add,btn_edit,btn_del,btn_logout):
	table.destroy()
	btn_add.destroy()
	btn_edit.destroy()
	btn_del.destroy()
	btn_logout.destroy()
	DATA.USER=None
	login()
	

def DoubleClick(table,user,*event):#show password

	selected = table.focus()
	temp = table.item(selected, 'values')

	if temp=="":
		PopUp("Selecione alguma \n coisa!")

	if temp[4]==CHEKED_BOX:#vamos ent tapar a passs
		table.item(selected, values=(temp[0], temp[1], temp[2], "********", UNCHEKED_BOX))
	else:
		passwrd=None
		for i in DATA.DATA[user]:
			if int(temp[0])==i["id"]:
				passwrd=i["pass"]
				break

		passwrd=simetric_decript(int(temp[0]),user,passwrd)

		table.item(selected, values=(temp[0], temp[1], temp[2], passwrd, CHEKED_BOX))


def loged(titulo,user_title,user_input,password_title,password_input,btn_login,user,btn_regist):

	titulo.destroy()
	user_title.destroy()
	user_input.destroy()
	password_title.destroy()
	password_input.destroy()
	btn_login.destroy()
	btn_regist.destroy()

	table = ttk.Treeview(GUI,height = 12)
	table['columns']=('ID','Site', 'User', 'Password', 'Show')
	table.column('#0', width=0, stretch=NO)
	table.column('ID', width=0, stretch=NO)
	table.column('Site', anchor=CENTER, width=115)
	table.column('User', anchor=CENTER, width=115)
	table.column('Password', anchor=CENTER, width=115)
	table.column('Show', anchor=CENTER, width=40)

	table.heading('Site', text='Site', anchor=CENTER)
	table.heading('User', text='User', anchor=CENTER)
	table.heading('Password', text='Password', anchor=CENTER)
	table.heading('Show', text='Show', anchor=CENTER)


	for i in DATA.DATA[user]:
		table.insert(parent='', index="end", iid=i["id"], text='', values=(i["id"],i["site"],i["user"],"********",UNCHEKED_BOX))


	table.place(x=90,y=20)

	btn_add = Button(GUI,text = "Add",command = lambda: Click_add(user,table))
	btn_add.place(x=20,y=20)
	btn_edit = Button(GUI,text = "Edit",command = lambda: Click_edit(table,user))
	btn_edit.place(x=20,y=50)
	btn_del = Button(GUI,text = "Delete",command = lambda: Click_del(table,user))
	btn_del.place(x=20,y=80)
	btn_logout = Button(GUI,text = "Logout",command = lambda: Click_logout(table,btn_add,btn_edit,btn_del,btn_logout))
	btn_logout.place(x=20,y=250)

	table.bind("<Double-1>", lambda event: DoubleClick(table,user))
	table.bind('<Return>', lambda event: Click_edit(table,user))
	table.bind("<Delete>", lambda event: Click_del(table,user))

	GUI.after(600000 ,lambda: session_timeup(table,btn_add,btn_edit,btn_del,btn_logout))#session_timeup 10 min

def session_timeup(table,btn_add,btn_edit,btn_del,btn_logout):
	table.destroy()
	btn_add.destroy()
	btn_edit.destroy()
	btn_del.destroy()
	btn_logout.destroy()
	DATA.USER=None
	login()
	PopUp("Session Time Up!")


def PopUp(msg):
   pop_up= Toplevel(GUI)
   pop_up.geometry("250x150+865+465")
   pop_up.title("Warning")
   Label(pop_up, text= msg, font=('Arial',16)).place(x=125,y=75,anchor="center")

def Click_regist_ok(pop_add,user_input,pass_input_add,pass_input_confirm,*event):#!verificar por sql injection o username

	user = user_input.get()
	passwrd = pass_input_add.get()
	passwrd_confirm = pass_input_confirm.get()

	if passwrd!=passwrd_confirm:
		PopUp("Passwords don't \n match!")
		pass_input_add.delete(0,'end')
		pass_input_confirm.delete(0,'end')
		return None

	if len(user)<4:
		PopUp("User should contain \n at least 4 chars")
		user_input.delete(0,'end')
		return None

	#!encriptaçao da pass com salt e do user 
	id=0
	for i in DATA.DATA["UAP_Users"]:# ver id max
		if id<i["id"]:
			id=i["id"]
	id+=1

	result = hashlib.sha256(user.encode())
	user=result.hexdigest()

	salt=str(id)
	result = hashlib.sha256(salt.encode())
	salt=result.hexdigest()

	passwrd=passwrd+salt

	result = hashlib.sha256(passwrd.encode())
	passwrd=result.hexdigest()

	for i in DATA.DATA["UAP_Users"]:
		if i["user"]==user or user=="UAP_Users":
			PopUp("Username already \n exists!")
			user_input.delete(0,'end')
			return None

	DATA.DATA["UAP_Users"].append({
		"id":id,
		"pass":passwrd,
		"user":user
	})

	DATA.DATA[user]=[]
	
	pop_add.destroy()
	

def Click_register():
	pop_add= Toplevel(GUI)
	pop_add.geometry("300x200+840+440")
	pop_add.title("Regist")

	user_title = Label(pop_add, text="User",font=("Arial", 12))
	user_title.place(x=18,y=20)
	user_input = Entry(pop_add, width=35)
	user_input.place(x=60,y=20,height=20)

	pass_title_add = Label(pop_add, text="Pass",font=("Arial", 12))
	pass_title_add.place(x=18,y=60)
	pass_input_add = Entry(pop_add, show="*", width=35)
	pass_input_add.place(x=60,y=60,height=20)

	pass_title_confirm = Label(pop_add, text="Pass",font=("Arial", 12))
	pass_title_confirm.place(x=18,y=100)
	pass_input_confirm = Entry(pop_add,show="*" , width=35)
	pass_input_confirm.place(x=60,y=100,height=20)

	btn_pop_ok = Button(pop_add,text = "Ok",command = lambda: Click_regist_ok(pop_add,user_input,pass_input_add,pass_input_confirm))
	btn_pop_ok.place(x=110,y=150)
	btn_pop_cancel = Button(pop_add,text = "Cancel",command = lambda: pop_add.destroy())
	btn_pop_cancel.place(x=150,y=150)

	pop_add.bind('<Return>', lambda event: Click_regist_ok(pop_add,user_input,pass_input_add,pass_input_confirm))


def Click_login(titulo,user_title,user_input,password_title,password_input,btn_login,btn_regist,*event):
	user = user_input.get()
	user_input.delete(0,'end')

	password = password_input.get()
	password_input.delete(0,'end')

	#!encriptaçao da pass com salt e do user
	result = hashlib.sha256(user.encode())
	user=result.hexdigest()

	for i in DATA.DATA["UAP_Users"]:
		if i["user"]==user:
			salt=str(i["id"])
			result = hashlib.sha256(salt.encode())
			salt=result.hexdigest()
			password=password+salt
			result = hashlib.sha256(password.encode())
			password=result.hexdigest()

			if i["pass"]==password:
				DATA.USER=user
				loged(titulo,user_title,user_input,password_title,password_input,btn_login,user,btn_regist)
				return
			else:
				PopUp("Wrong password!")
				return
	
	PopUp("User doesn't exist!")


def login():
	titulo = Label(GUI, text="UAP",font=("Arial", 25))
	titulo.place(x=210,y=30)

	user_title = Label(GUI, text="Username",font=("Arial", 15))
	user_title.place(x=50,y=120)
	user_input = Entry(GUI, width=46)
	user_input.place(x=160,y=120,height=28)

	password_title = Label(GUI, text="Password",font=("Arial", 15))
	password_title.place(x=50,y=170)
	password_input = Entry(GUI,show="*", width=46)
	password_input.place(x=160,y=170,height=28)

	btn_regist = Button(GUI,text = "Regist",command = lambda: Click_register())
	btn_regist.place(x=250,y=230)

	btn_login = Button(GUI,text = "Login",command = lambda: Click_login(titulo,user_title,user_input,password_title,password_input,btn_login,btn_regist))
	btn_login.place(x=190,y=230)
	GUI.bind('<Return>',lambda event: Click_login(titulo,user_title,user_input,password_title,password_input,btn_login,btn_regist)) #click enter	

def server_connection(server_socket):	
	server_socket.settimeout(0.01)
	try:
		conn, address = server_socket.accept()
	except:
		GUI.after(1,lambda: server_connection(server_socket))
		return None

	e_chap(conn, address)
	conn.close()
	server_socket.listen(1)
	GUI.after(1,lambda: server_connection(server_socket))

def e_chap(conn,address):
	if DATA.USER==None:
		return
	
	site=conn.recv(1024).decode()

	PopUp("Autenticating on\n"+site+"\nusing e-chap!")

	user=" "
	passwrd=None
	for i in DATA.DATA[DATA.USER]:
		if site==i["site"]:
			user=i["user"]
			passwrd=simetric_decript(i["id"],DATA.USER,i["pass"])
			break

	conn.send(user.encode())

	response=conn.recv(1024).decode()
	if response=="ERROR":
		conn.close()
		return

	SC=conn.recv(1024)
	
	CC = os.urandom(84)
	conn.send(CC)

	response=conn.recv(1024).decode()
	if response=="ERROR":
		conn.close()
		return

	final_UAP = algorithm(user.encode(),passwrd.encode(),SC,CC,conn)

	conn.send(final_UAP)

	res=conn.recv(1024).decode()

	if res=="true":
		PopUp("Login successful!")
	else:
		PopUp("Error in login!")

	conn.close()


def on_closing():#save data.json encripted
	DATA=encript_file()

	file = open("data.json","wb")
	file.write(DATA)
	file.close()

	GUI.destroy()

def decript_file():
	f = open("data.json", "rb")
	ct=f.read()
	f.close()

	cipher2 = Cipher(algorithms.AES(MASTER_FILE_KEY), modes.CBC(MASTER_FILE_IV))
	decryptor = cipher2.decryptor()

	n = 32
	chunks = [ct[i:i+n] for i in range(0, len(ct), n)]

	dt=decryptor.update(chunks[0])
	for i in range(1,len(chunks)):
		dt+= decryptor.update(chunks[i])
	
	dt+=decryptor.finalize()

	return json.loads(dt.decode())

def encript_file():

	temp=json.dumps(DATA.DATA)

	n = 32
	chunks = [temp[i:i+n] for i in range(0, len(temp), n)]
	
	while len(chunks[-1])!=32:
		chunks[-1]+=" "

	cipher = Cipher(algorithms.AES(MASTER_FILE_KEY), modes.CBC(MASTER_FILE_IV))
	encryptor = cipher.encryptor()

	ct=encryptor.update(chunks[0].encode())
	for i in range(1,len(chunks)):
		ct+= encryptor.update(chunks[i].encode())
	
	ct+=encryptor.finalize()

	return ct


file_data = decript_file()
DATA=UAP_Data(file_data,None)

GUI = Tk()
GUI.title("UAP")
GUI.geometry("500x300+740+390")
GUI.resizable(False, False)

bg = PhotoImage( file = "files/bg.png")
bg_label = Label( GUI, image = bg)
bg_label.place(x = -2,y = 0)

login()

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # get instance
server_socket.bind(("127.0.0.1", 6000))  # bind host address and port together
server_socket.listen(1)

GUI.after(1,lambda: server_connection(server_socket))
GUI.protocol("WM_DELETE_WINDOW", on_closing)
GUI.mainloop()


