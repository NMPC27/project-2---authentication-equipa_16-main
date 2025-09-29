import hashlib
from flask import Flask
from flask import request
from flask import render_template
from flask import session
import sqlite3 as sql
import re
from flask import send_file
import os
from werkzeug.utils import secure_filename
from werkzeug.utils import safe_join

from auth import *

MASTER_USERS_PASS_KEY = "bS5W2+$mGf2V-UE2?,6q*9%t{/ez" #28 -> 4 para o user
MASTER_USERS_IV_KEY = "Y!v:7b{*ey&=" #12 -> 4 para o user

email_check = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
def verify_email(email):
	if(re.fullmatch(email_check, email)):
		return True
	else:
		return False

password_check= re.compile('[@_!#$%^&*()<>?/\|}{~:]')
def verify_password(password):
	upper=False
	numeric=False
	lower=False
	special=False

	for char in password:
		if char.isupper():
			upper=True
		if char.isnumeric():
			numeric=True
		if char.islower():
			lower=True
		if(password_check.search(password) != None):
			special=True

	if len(password)>10 and upper and numeric and lower and special:# pass com estas caracteristicas demora 400 anos a dar brute force
		return True
	
	return False


app = Flask(__name__)

app.secret_key = b'@A~,;N^s`d7b\a"P' #-> time to brute force = 1Tn years

@app.route("/") 
def index():
	if 'username' in session:
		return render_template('index.html',user=session["username"])

	return render_template('index.html')

@app.route("/products")
def products():
	db = sql.connect("webDB.db")
	result = db.execute("SELECT ID_product,name,img_path FROM products;")
	rows = result.fetchall()
	db.close()

	lista_produtos=[]
	for row in rows:
		id=row[0]
		name=row[1]
		img=row[2].split("%")
		lista_produtos.append([id,name,img[0]])

	if 'username' in session:
		return render_template('products.html',lista=lista_produtos,user=session["username"])

	return render_template('products.html',lista=lista_produtos)

@app.route("/about")
def about():
	if 'username' in session:
		return render_template('about.html',user=session["username"])

	return render_template('about.html')

@app.route("/login_page")
def login_page(*args):
	if len(args)>0 :
		return render_template('login.html',alert=args[0])
	return render_template('login.html')

@app.route("/login",methods=['POST'])#!CHANGE
def login():
	user=request.form['user']
	password_input=request.form['password']

	db = sql.connect("webDB.db")
	result = db.execute("SELECT ID,user,pass FROM users WHERE user=?;",(user,))
	data = result.fetchall()
	db.close()

	key=MASTER_USERS_PASS_KEY+user[0:4]
	iv=user[0:4]+MASTER_USERS_IV_KEY
	cipher2 = Cipher(algorithms.AES(key.encode()), modes.CBC(iv.encode()))
	decryptor = cipher2.decryptor()

	salt=str(data[0][0])
	result = hashlib.sha256(salt.encode())
	salt=result.hexdigest()

	n = 32
	chunks = [data[0][2][i:i+n] for i in range(0, len(data[0][2]), n)]

	dt=decryptor.update(chunks[0])
	for i in range(1,len(chunks)):
		dt+= decryptor.update(chunks[i])
	
	dt+=decryptor.finalize()

	passwrd=dt.decode()
	idx=passwrd.index(salt)
	passwrd=passwrd[0:idx]

	if data != []:# user existe and password correta
		if passwrd == password_input:
			session['username'] = user
			return account()
	
	return login_page(1)#erro user n existe/pass errada

@app.route("/sign_up",methods=['POST'])
def sign_up():
	user=request.form['user']
	password=request.form['password']
	email=request.form['email']
	file = request.files['avatar']

	db = sql.connect("webDB.db")
	result = db.execute("SELECT user FROM users WHERE user=?;",(user,))
	data = result.fetchall()
	db.close()

	if data!=[]:
		return login_page(4)#username ja usado
	if not(verify_email(email)):
		return login_page(2)#email n valido
	if not(verify_password(password)):
		return login_page(3)#pass n valida

	#adicionar à db
	user_path=safe_join(os.path.dirname(os.path.abspath(__file__)),"user_data",user)
	os.mkdir(user_path)
	filename = secure_filename(file.filename)
	file.save(safe_join(user_path, filename))

	key=MASTER_USERS_PASS_KEY+user[0:4]
	iv=user[0:4]+MASTER_USERS_IV_KEY
	
	db = sql.connect("webDB.db")
	result = db.execute("SELECT seq FROM sqlite_sequence WHERE name='users';")
	data = result.fetchall()

	id=data[0][0] + 1

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

	db.execute("INSERT INTO users VALUES (?,?,?,?,?,?);",(None,user,ct,0,email,filename))
	db.commit()
	db.close()

	session['username'] = user
	return account()

@app.route("/account")
def account():
	if 'username' in session:
		db = sql.connect("webDB.db")
		result = db.execute("SELECT * FROM users WHERE user=?;",(session["username"],))
		data = result.fetchall()
		db.close()

		return render_template('account.html',user=data[0][1],money=data[0][3],email=data[0][4])
	return login_page()

@app.route('/<item>')
def products_item(item):

	if item=="all":
		return products()

	db = sql.connect("webDB.db")
	result = db.execute("SELECT ID_product,name,img_path FROM products")
	rows = result.fetchall()
	db.close()

	lista_produtos=[]
	for row in rows:
		name=row[1]
		if item in name.lower():
			id=row[0]
			img=row[2].split("%")
			lista_produtos.append([id,name,img[0]])

	if 'username' in session:
			return render_template('products.html',lista=lista_produtos,user=session["username"])

	return render_template('products.html',lista=lista_produtos)

@app.route('/search', methods=['POST'])
def products_search():
	
	item=request.form['search_name']

	db = sql.connect("webDB.db")
	result = db.execute("SELECT ID_product,name,img_path FROM products")
	rows = result.fetchall()
	db.close()

	lista_produtos=[]#lista de tuplos

	for row in rows:      
		name=row[1]
		if item in name.lower():
			id=row[0]
			img=row[2].split("%")
			lista_produtos.append([id,name,img[0]])

	if 'username' in session:
			return render_template('products.html',lista=lista_produtos,user=session["username"])

	return render_template('products.html',lista=lista_produtos)


@app.route('/buy/<item>')
def buy_item(item):
	db = sql.connect("webDB.db")
	result = db.execute("SELECT * FROM products WHERE ID_product=?",(int(item),))
	data = result.fetchall()
	db.close()

	name=data[0][1]
	img=data[0][2].split("%")
	price=data[0][3]
	description=data[0][4]

	if 'username' in session:
			return render_template('buy.html',id=item,name=name,img=img,price=price,description=description,user=session["username"])

	return render_template('buy.html',id=item,name=name,img=img,price=price,description=description)

@app.route('/logout')
def logout():
	# remove the username from the session if it's there
	session.pop('username', None)
	return index()

@app.route('/checkout/<item>')
def checkout(item):  
	db = sql.connect("webDB.db")
	result = db.execute("SELECT name,price FROM products WHERE ID_product=?;",(int(item),))
	product = result.fetchall()
	
	result = db.execute("SELECT ID,money FROM users WHERE user=?;",(session['username'],))
	user = result.fetchall()

	res=user[0][1]-product[0][1]

	if res>=0:#pode comprar 
		db.execute("UPDATE users SET money=? WHERE ID=?;",(res,user[0][0]))
		db.commit()
		db.close()
		return bought(product[0][0])

	else:#n pode comprar
		db.close()
		return bought()

@app.route('/bought')
def bought(*product_name): 
	if product_name==():
		return render_template("bought.html",product_name=None,user=session['username'])

	return render_template("bought.html",product_name=product_name[0],user=session['username'])

@app.route('/changePassword') 
def changePassword(*args):   
	if 'username' in session:
			if len(args)>0:
				return render_template('changePassword.html',alert=args[0])
			return render_template('changePassword.html')

	return index()

@app.route('/password_changed', methods=['POST']) 
def password_changed():   
	if 'username' in session:

		currentPassInput=request.form['currentPass']
		
		result = hashlib.sha256(currentPassInput.encode())
		encripted_currentPassInput=result.hexdigest()

		db = sql.connect("webDB.db")
		result = db.execute("SELECT pass FROM users WHERE user=?;",(session['username'],))
		currentPass = result.fetchall()
		db.close()

		if currentPass[0][0] == encripted_currentPassInput:
			pass1=request.form['newPass1']  
			pass2=request.form['newPass2']
			if pass1==pass2:
				if verify_password(pass1):
					result = hashlib.sha256(pass1.encode())
					encripted_pass=result.hexdigest()

					db = sql.connect("webDB.db")
					db.execute("UPDATE users SET pass=? WHERE user=?;",(encripted_pass,session['username']))
					db.commit()
					db.close()
					return account()
				return changePassword(2)
			else:
				return changePassword(1)
		else:
			return changePassword(3)

	return index()

@app.route('/client_support') 
def client_support():   

	user=None
	if 'username' in session:
		user=session['username']

	db = sql.connect("webDB.db") 
	result = db.execute("SELECT name,msg FROM client_support;")
	msgs = result.fetchall()
	db.close()

	return render_template('client_support.html',user=user,msg_list=msgs)

@app.route('/client_support_update', methods=['POST']) #clicou no form
def client_support2():   

	user=None
	if 'username' in session:
		user=session['username']

	nome=request.form['name']
	msg=request.form['msg']

	db = sql.connect("webDB.db")
	db.execute("INSERT INTO client_support VALUES (?,?,?);",(None,nome,msg))
	db.commit()
		
	result = db.execute("SELECT name,msg FROM client_support;")
	msgs = result.fetchall()
	db.close()

	return render_template('client_support.html',user=user,msg_list=msgs)

@app.route("/show_avatar")
def show_avatar():

	if 'username' in session:
		db = sql.connect("webDB.db") 
		result = db.execute("SELECT avatar FROM users WHERE user=?;",(session['username'],))
		user_avatar = result.fetchall()
		db.close()

		path=safe_join(os.path.dirname(os.path.abspath(__file__)),"user_data",session['username'],user_avatar[0][0])

		return send_file(path, as_attachment=False)

	return index()

@app.route("/uap")
def uap():
	user=login_uap()
	if user!=None:
		session['username'] = user
		return render_template('uap.html',user=user,error=0)
	else:
		return render_template('uap.html',error=1)



app.run(debug=False)#!MUDAR para false
