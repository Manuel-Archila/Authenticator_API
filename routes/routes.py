import random
from flask import Blueprint, jsonify, request
import psycopg2
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt



# Crear un Blueprint
routes = Blueprint('routes', __name__)

# Establece la conexión a la base de datos
try:
    connection = psycopg2.connect(
        host='localhost',
        database='authenticator',
        user='auth',
        password='queso123'
    )
except Exception as error:
    print(f"No se pudo conectar a la base de datos debido a: {error}")
    connection = None


# Función para cargar la llave privada desde un archivo
def cargar_llave_privada(filename):
    with open(filename, "rb") as f:
        private_key = f.read()
    return private_key

# Función para obtener la llave pública a partir de la llave privada
def obtener_llave_publica(private_key):
    private_key = serialization.load_pem_private_key(
        private_key,
        password=None
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_pem.decode('utf-8')  # Convertir bytes a str


@routes.route('/users', methods=['POST'])
def register_user():
    # Obtener la información del usuario
    user_data = request.json
    username = user_data.get('username')
    password = user_data.get('password')

    # Crear un cursor
    cursor = connection.cursor()

    # Crear el query
    query = f"INSERT INTO usuarios (username, contrasena) VALUES ('{username}', '{password}')"

    # Ejecutar el query
    cursor.execute(query)

    # Guardar los cambios
    connection.commit()

    # Cerrar el cursor
    cursor.close()

    return jsonify({"valid": True, "message": "Usuario creado exitosamente"}), 201

# Function that logs in a user
@routes.route('/login', methods=['POST'])
def login_user():
    # Get the user information
    user_data = request.json
    username = user_data.get('username')
    password = user_data.get('password')

    # Create a cursor
    cursor = connection.cursor()

    # Create the query
    query = f"SELECT * FROM usuarios WHERE username = '{username}' AND contrasena = '{password}'"

    # Execute the query
    cursor.execute(query)

    # Get the results
    user = cursor.fetchone()

    publick_key = obtener_llave_publica(cargar_llave_privada("./private_key.pem"))

    # Close the cursor
    cursor.close()

    if user:
        return jsonify({"valid": True, "message": "Usuario autenticado exitosamente", "public_key": publick_key}), 200
    else:
        return jsonify({"valid": False, "message": "Usuario o contraseña incorrectos", "public_key": None}), 401


# Function that receives data and private key pem and returns a jwt token
@routes.route('/generate-token', methods=['POST'])
def generate_token():
    user_data = request.json
    nombre = user_data.get('nombre')
    historia = user_data.get('historia')
    private_key = cargar_llave_privada("./private_key.pem")

    # Crear un diccionario con el nombre y la historia
    payload = {"historia": historia}

    if random.randint(0, 1) == 0:
        historia = jwt.encode(payload, private_key, algorithm='RS256')

    cursor = connection.cursor()

    query = f"INSERT INTO historias (nombre, historia) VALUES ('{nombre}', '{historia}')"

    cursor.execute(query)

    connection.commit()

    cursor.close()

    return jsonify({"valid": True, "message": "Token generado"}), 200

# Function that returns all the stories
@routes.route('/historias', methods=['GET'])
def get_stories():
    cursor = connection.cursor()

    query = "SELECT * FROM historias"

    cursor.execute(query)

    historias = cursor.fetchall()

    historias = [{"id": historia[0], "nombre": historia[1], "historia": historia[2]} for historia in historias]

    cursor.close()

    return jsonify(historias), 200

@routes.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    encrypted_data = data.get('data')
    public_key_text = data.get('public_key')

    # Convertir la clave pública de texto a objeto Key
    public_key_bytes = public_key_text.encode('utf-8')
    public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())

    try:
        # Decodificar los datos utilizando la clave pública
        decoded_data = jwt.decode(encrypted_data, public_key, algorithms=["RS256"])
        return jsonify(decoded_data), 200
    except jwt.PyJWTError as e:
        return jsonify({"error": str(e)}), 400

