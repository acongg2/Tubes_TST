from flask import Flask, jsonify, request
from flask_bcrypt import generate_password_hash, check_password_hash
from flask_jwt_extended import  JWTManager, jwt_required, create_access_token
from datetime import timedelta
import psycopg2
import requests
from requests.auth import HTTPBasicAuth


app = Flask(__name__)
app.config['JWT_SECRET_KEY'] = 'secret'
jwt = JWTManager(app)


host = "satao.db.elephantsql.com"
database = "bueienbb"
user = "bueienbb"
password = "xE5Gm52jFK0Xj7geX_F5qiUk8oLgnBWu"


mydb = psycopg2.connect(host=host, database=database, user=user, password=password)


#Register and Login
#Register
@app.route('/register', methods=['POST'])
def register():
    
    username = request.json.get('username', None)
    password = request.json.get('password', None)

    if not username or not password:
        return ({"error": "Username and Password are required"}), 400
    if username == password:
        return ({"error": "Username and Password must be different"}), 400
    if len(username) < 4:
        return ({"error": "Username must be at least 4 characters"}), 400
    if len(password) < 6:
        return ({"error": "Password must be at least 6 characters"}), 400

    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("SELECT * FROM users WHERE username=%s", (username,))
    check = mydb_cursor.fetchone()
    if check is not None:
        return ({"error": "Username already exists"}), 400

    hashed_password = generate_password_hash(password).decode('utf-8')

    mydb_cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, hashed_password))
    mydb.commit()
    mydb_cursor.close()
    return ({"message": "User created successfully"}), 200
    

#Login
@app.route('/login', methods=['POST'])
def login_user():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return ('Please insert username or password', 401, {'WWW.Authentication': 'Basic realm: "login required"'})
    
    mydb_cursor = mydb.cursor()
    user = mydb_cursor.execute("SELECT * FROM users WHERE username=%s", (auth.username,))
    user = mydb_cursor.fetchone()
    
    if user is not None:
        if check_password_hash(user[1], auth.password):
            token = create_access_token(identity=auth.username, expires_delta=timedelta(minutes=25))
            return jsonify(access_token = token), 200
    
    mydb_cursor.close()
    return ('Invalid username or password'), 401




#CRUD Operations
# GET
@app.route('/get_data', methods=['GET'])
@jwt_required()
def get():
    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("SELECT * From person_income")
    return jsonify({'person_income': mydb_cursor.fetchall()}), 200  

#POST
@app.route('/add_data', methods=['POST'])
@jwt_required()
def create():
    data = request.get_json()
    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("INSERT INTO person_income (ID, Gender, Married, Dependents, Self_Employed, ApplicantIncome, CoApplicantIncome, LoanAmount, LoanAmount_Term, Credit_History, Property_Area) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", (data['ID'], data['Gender'], data['Married'], data['Dependents'], data['Self_Employed'], data['ApplicantIncome'], data['CoApplicantIncome'], data['LoanAmount'], data['LoanAmount_Term'], data['Credit_History'], data['Property_Area']))
    mydb.commit()
    mydb_cursor.close()
    return jsonify({'person_income': data}), 201 

#PUT
@app.route('/update_data', methods=['PUT'])
@jwt_required()
def update():
    data = request.get_json()
    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("UPDATE person_income SET ID = %s, Gender = %s, Married = %s, Dependents= %s, Self_Employed = %s, ApplicantIncome = %s, CoApplicantIncome = %s, LoanAmount = %s, LoanAmount_Term = %s, Credit_History = %s, Property_Area = %s WHERE ID = %s", 
    (data['ID'], data['Gender'], data['Married'], data['Dependents'], data['Self_Employed'], data['ApplicantIncome'], data['CoApplicantIncome'], data['LoanAmount'], data['LoanAmount_Term'], data['Credit_History'], data['Property_Area'], data['ChangeID']))
    mydb.commit()
    mydb_cursor.close()
    return jsonify({'person_income': data}), 200

#DELETE
@app.route('/remove_data', methods=['DELETE'])
@jwt_required()
def delete():
    data = request.get_json()

    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("SELECT * FROM person_income WHERE ID = %s", (data['ID'],))
    if not mydb_cursor.fetchone():
        return jsonify({'person_income': 'Not Found'}), 404

    mydb_cursor.execute("DELETE FROM person_income WHERE ID = %s", (data['ID'],))
    mydb.commit()
    mydb_cursor.close()
    return jsonify({'person_income': 'Deleted'}), 200 




#CORE

#CORE FUNCTIONS
#GET Loan by ID
def getloan_by_id(id):
    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("SELECT LoanAmount From person_income WHERE ID = %s", (id,))
    rows = mydb_cursor.fetchone()
    mydb_cursor.close()
    return rows

#GET LoanTerm by ID
def getloanterm_by_id(id):
    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("SELECT LoanAmount_Term From person_income WHERE ID = %s", (id,))
    rows = mydb_cursor.fetchone()
    mydb_cursor.close()
    return rows

#GET Income by ID
def getapplicantincome(id):
    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("SELECT ApplicantIncome FROM person_income WHERE ID = %s", (id,))
    total = mydb_cursor.fetchone()
    mydb_cursor.close()
    return total

#GET CoApplicantIncome by ID
def getcoapplicantincome(id):
    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("SELECT CoApplicantIncome FROM person_income WHERE ID = %s", (id,))
    total = mydb_cursor.fetchone()
    mydb_cursor.close()
    return total

#GET dependencies by ID
def getdependencies(id):
    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("SELECT Dependents FROM person_income WHERE ID = %s", (id,))
    total = mydb_cursor.fetchone()
    mydb_cursor.close()
    return total



#CORE SERVICES

#GET Total Spending
def totalspending(id):
    pendapatan1 = getapplicantincome(id)
    pendapatan2 = getcoapplicantincome(id)
    totalpendapatan = pendapatan1[0] + pendapatan2[0]
    utang = getloan_by_id(id)

    bunga_hutang = utang[0] * 1/100

    kebutuhan = totalpendapatan * 55/100

    totalspending = bunga_hutang + kebutuhan
    
    return totalspending, 200

#Check dditional Spending
def checkaddspending(id):
    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("SELECT * FROM person_income WHERE ID=%s", (id,))
    check = mydb_cursor.fetchone()

    if check is None:
        return ({"error": "ID Unavailable"}), 400

    totalspend = totalspending(id)
    pendapatan1 = getapplicantincome(id)
    pendapatan2 = getcoapplicantincome(id)
    totalpendapatan = pendapatan1[0] + pendapatan2[0]
    Tabungan = (totalpendapatan - totalspend[0]) * 40/100
    additionalspending = totalpendapatan - totalspend[0] - Tabungan 

    return additionalspending

#GET
@app.route('/buy_power', methods=['GET'])
@jwt_required()
def buying_power() :
    data = request.get_json()
    id = data['ID']

    tanggungan = getdependencies(id,)
    pengeluaranmaks = checkaddspending(id,)                             # add = additional
    buypower = pengeluaranmaks * (24 - (2*tanggungan[0]))               # Harga mobil sesuai : pengeluaran * (24 * (2 * tanggungan)))
    return jsonify({'Kemampuan pembelian kamu adalah' : buypower})


def buying_power(id) :
    tanggungan = getdependencies(id,)
    pengeluaranmaks = checkaddspending(id,)
    buypower = pengeluaranmaks * (24 - (2*tanggungan[0]))           # Harga mobil sesuai : pengeluaran * (24 * (2 * tanggungan)))
    return buypower



#CORE SERVICES

#API PROVIDER 

#GET Max Additional Spending
@app.route('/additional_spending', methods=['GET'])
@jwt_required()
def addspending():
    data = request.get_json()

    mydb_cursor = mydb.cursor()
    mydb_cursor.execute("SELECT * FROM person_income WHERE ID=%s", (data["ID"],))
    check = mydb_cursor.fetchone()

    if check is None:
        return ({"error": "ID Unavailable"}), 400

    totalspend = totalspending(data['ID'])
    pendapatan1 = getapplicantincome(data['ID'])
    pendapatan2 = getcoapplicantincome(data['ID'])
    totalpendapatan = pendapatan1[0] + pendapatan2[0]
    Tabungan = (totalpendapatan - totalspend[0]) * 40/100
    additionalspending = totalpendapatan - totalspend[0] - Tabungan 

    return jsonify({'total_pengeluaran_tambahan': additionalspending}), 200



# To Access Partner API
import requests

def get_bearer_token():
    response = requests.post('https://carsalesray.azurewebsites.net/login', auth=HTTPBasicAuth('calvin', 'Test123'))
    jsonresponse = response.json()
    bearertoken = str(jsonresponse['access_token'])
    return bearertoken


def get_structure(url, batas_harga):
    headers = {"Authorization": f'Bearer {get_bearer_token()}', 'Content-Type' : 'application/json'}
    print(headers)
    response = requests.get(url, headers=headers, json=batas_harga)
    print(response)
    jsonresponse = response.json()
    print(jsonresponse)
    return jsonresponse



#API REQUEST FROM FRIEND
#Car Recommendation Based on Finance
@app.route('/car_recommendation_based_finance', methods=['GET'])
def Car_Recommendation_Based_Finance():
    data = request.get_json()

    id = data['ID']
    price_limit = buying_power(id)

    url = 'https://carsalesray.azurewebsites.net/list_rekomendasi_mobil'
    request_body = {
        'batas_harga' : price_limit
        }
    jsonresponse = get_structure(url, request_body)
    
    return jsonify({'Rekomendasi mobil yang cocok untuk anda' : jsonresponse}), 200



if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=5002)