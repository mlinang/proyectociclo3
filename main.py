from flask import Flask
from flask import render_template
from flask import request
from flask import flash
from flask import redirect, url_for
from flask import jsonify
from flask import session
from flask import g
from flask import send_file
from flask import make_response
import functools
from werkzeug.security import generate_password_hash, check_password_hash 

import os
from utils import isUsernameValid, isEmailValid, isPasswordValid
import yagmail as yagmail
from forms import Formulario_Usuario, Formulario_Contacto, Formulario_Enviar_Mensaje
from db import get_db, close_db

app = Flask(__name__)
app.secret_key = os.urandom(24)

from mensaje import mensajes
   
# Usuario requerido:
# Es como si se estuviese llamando directamente a la función interna
def login_required(view):
    @functools.wraps( view ) # toma una función utilizada en un decorador y añadir la funcionalidad de copiar el nombre de la función.
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect( url_for( 'login' ) ) # si no tiene datos, lo envío a que se loguee
        return view( **kwargs )
    return wrapped_view

@app.route('/')
@login_required
def index():    
    return redirect( url_for('send') )

@app.route('/send', methods=['GET', 'POST'])
@login_required   # el objetivo es ver si g.user tiene datos
def send():
    form = Formulario_Enviar_Mensaje( request.form  )
    if request.method == 'POST':
        # POST:                
        from_id = g.user[0]
        to_usuario = form.para.data # to_id 
        asunto  = form.asunto.data
        mensaje = form.mensaje.data

        error = None
        db = get_db()
        nom_cookie = request.cookies.get( 'username' , 'Usuario' ) # nombre de la cookie y valor en caso que no esté esa cookie

        if not to_usuario:
            error = 'PARA es requerido.'
            flash( error )
        if not asunto:
            error = 'ASUNTO es requerido.'
            flash( error )
        if not mensaje:
            error = 'MENSAJE es requerido.'
            flash( error )

        usuario_destino = db.execute(
                'SELECT id, nombre, usuario, correo, contrasena FROM Usuarios WHERE usuario = ?'
                ,
                (to_usuario,)
            ).fetchone()
        if usuario_destino is None:
            error = '{}, no existe el usuario destino.'.format(nom_cookie)
            flash( error )

        if error is not None:
            return render_template("send.html", form=form)
        else:
            db.execute(
                    'INSERT INTO Mensajes (from_id,to_id,asunto,mensaje) VALUES (?,?,?,?)'
                    ,
                    (from_id,usuario_destino[0],asunto,mensaje)
                )
            db.commit()
            close_db()
            flash( '{}, mensaje enviado.'.format(nom_cookie) )
            form = Formulario_Enviar_Mensaje( )                  
    # GET:
    return render_template("send.html", form=form)

@app.route('/registro', methods=['GET', 'POST'])
def registro():
    #try:
        if g.user:
            return redirect( url_for('send') )
        if request.method == 'POST':   
            nombre = request.form['nombre']
            usuario = request.form['usuario']            
            email = request.form['email']
            password = request.form['password']

            error = None
            db = get_db()
            
            if not usuario:
                error = "Usuario requerido."
                flash(error)
            if not password:
                error = "Contraseña requerida."
                flash(error)
            #1. Validar usuario, email y contraseña:
            #if not isUsernameValid(usuario):
                # Si está mal.
            #    error = "El usuario debe ser alfanumerico o incluir solo '.','_','-'"
            #    flash(error)
            #if not isEmailValid(email):
                # Si está mal.
            #    error = "Correo invalido"
            #    flash(error)
            #if not isPasswordValid(password):
                # Si está mal.
            #    error = "La contraseña debe contener al menos una minúscula, una mayúscula, un número y 8 caracteres"
            #    flash(error)
            user_email = db.execute(
                'SELECT * FROM Usuarios WHERE correo = ?'
                ,
                (email,)
            ).fetchone()            
            if user_email is not None:
                error = "Correo ingresado ya existe."
                flash(error)

            if error is not None:
                # Ocurrió un error
                return render_template("registro.html")
            else:
                # Seguro:
                password_cifrado = generate_password_hash(password)
                db.execute(
                    'INSERT INTO Usuarios (nombre,usuario,correo,contrasena) VALUES (?,?,?,?) '
                    ,
                    (nombre,usuario,email,password_cifrado)
                )
                # No seguro:
                #db.executescript(
                #    "INSERT INTO Usuarios (nombre, usuario, correo, contrasena) VALUES ('%s','%s','%s','%s')" % (nombre, usuario, email, password)
                    #"; UPDATE usuario set correo='hack';"
                #) 
                db.commit()
                #2. Enviar un correo.
                # Para crear correo:                                    
                # Modificar la siguiente linea con tu informacion personal            
                #yag = yagmail.SMTP('pehernaldo2@gmail.com', 'Hernaldo12345678*') 
                #yag.send(to=email, subject='Activa tu cuenta',
                #    contents='Bienvenido, usa este link para activar tu cuenta ')
                flash('Revisa tu correo para activar tu cuenta')

                #3. redirect para ir a otra URL
                return redirect( url_for( 'login' ) )

        return render_template("registro.html")
    #except:
    #    flash("¡Ups! Ha ocurrido un error, intentelo de nuevo.")
    #    return render_template("registro.html")


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = Formulario_Usuario( request.form )
    if request.method == 'POST': # and form.validate():  
        # POST:          
        #Usuario: Prueba
        #Contraseña: Prueba123
        usuario = request.form['usuario']
        password = request.form['password']

        error = None
        db = get_db()

        if not usuario:
            error = "Usuario requerido."
            flash( error )
        if not password:
            error = "Contraseña requerida."
            flash( error )

        if error is not None:
            # SI HAY ERROR:
            return render_template("Login.html", form=form, titulo='Inicio de sesión')
        else:
            # No hay error:
            user = db.execute(
                'SELECT id, nombre, usuario, correo, contrasena FROM Usuarios WHERE usuario = ?'
                ,
                (usuario,)
            ).fetchone() 
            print(user)                     
            if user is None:
                error = "Usuario no existe." # Pendiente por seguridad modificar el mensaje
                flash(error)
            else:                
                usuario_valido = check_password_hash(user[4],password)
                if not usuario_valido:
                    error = "Usuario y/o contraseña no son correctos."
                    flash( error )                
                    return render_template("login.html", form=form, titulo='Inicio de sesión')
                else: 
                    session.clear()
                    session['id_usuario'] = user[0] # con esto estoy guardando el id_usuario logueado

                    #Modifica la función login para que cuando confirme la sesión, cree una cookie
                    #del tipo ‘username’ y almacene el usuario.
                    response = make_response( redirect( url_for('send') ) )
                    response.set_cookie( 'username', usuario  ) # nombre de la cookie y su valor
                    return response
    # GET:
    return render_template("Login.html", form=form, titulo='Inicio de sesión')

@app.before_request
def cargar_usuario_registrado():
    print("Entró en before_request.")
    # g.user = con los datos de la base de datos, basados en la session.
    id_usuario = session.get('id_usuario')
    if id_usuario is None:
        g.user = None
    else:
        g.user = get_db().execute(
                'SELECT id, nombre, usuario, correo, contrasena FROM Usuarios WHERE id = ?'
                ,
                (id_usuario,)
            ).fetchone()
    print('g.user:', g.user)

@app.route('/feed', methods=['GET', 'POST'])
def feed():
    return render_template("feed.html", titulo='Gracias')

@app.route('/contacto', methods=['GET','POST'])
def contacto():    
    form = Formulario_Contacto( request.form )
    if request.method == 'POST':        
        flash( form.nombre.data )
        flash( form.email.data )
        flash( form.mensaje.data )
        return render_template("contacto.html", form=form)
    # GET:
    return render_template("contacto.html", form=form)

@app.route('/mensaje')
def message():
    return jsonify( {"mensajes": mensajes } )

@app.route('/logout')
def logout():
    session.clear()
    return redirect( url_for( 'login' ) )

@app.route('/downloadpdf')
def downloadpdf():
    return send_file( "resources/doc.pdf", as_attachment=True )

@app.route('/downloadimage')
def downloadimage():
    return send_file( "resources/image.png", as_attachment=True )


 

