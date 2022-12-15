
import requests
from requests.auth import HTTPBasicAuth

response = requests.post('https://carsalesray.azurewebsites.net/login', auth=HTTPBasicAuth('calvin', 'Test123'))
jsonresponse = response.json()
bearertoken = str(jsonresponse['access_token'])
print (bearertoken)


headers = {"Authorization": f'Bearer {bearertoken}', 'Content-Type' : 'application/json'}
print(headers)
response = requests.get('https://carsalesray.azurewebsites.net/rekomendasi_mobil', headers=headers, json={'batas_harga' : 70000})
print(response)
response = response.json()
print (response)