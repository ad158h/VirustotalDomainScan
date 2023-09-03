import requests
import base64
import pprint
import os.path

api_key = {'x-apikey': '60f1ca94bb96eafc3b3bf0b4a80820c2e434c788e629d5bdf720ba34b5d6fea9'}
api_version = 3

base_url = 'https://www.virustotal.com/api/v3'

domain_input = input('Enter the Domain: ')
# GET /domains/{domain}
# domain_input = "necowater.com"
domain_request = requests.get(f'{base_url}/domains/{domain_input}/subdomains',headers=api_key)
print(domain_request.status_code)

main_data = domain_request.json().get('data')
whois_list = []
domain_list = []
print(domain_request.text)
for object in main_data:
    pprint.pprint(object.get('attributes').get('whois'))
for sub_data in main_data:
    whois = sub_data.get('whois')
    print(whois)
    whois_list.append(whois)
    sub_domain = sub_data.get('id')
    print(sub_domain)
    domain_list.append(sub_domain)
print(domain_list)

# url = "https://www.virustotal.com/api/v3/files"

# vtotal = Virustotal(API_VERSION="v3")
# FILE_PATH =r"C:\Users\adish\Desktop\New folder.zip"
# files = {"file": (os.path.basename(FILE_PATH), open(os.path.abspath(FILE_PATH), "rb"))}

# response = vtotal.request("files", files=files, method="POST")
# headers = {
#     "x-apikey":"60f1ca94bb96eafc3b3bf0b4a80820c2e434c788e629d5bdf720ba34b5d6fea9",
#     "Accept": "application/json",
#     "Content-Type": "multipart/form-data"
# }

# response = requests.request("POST", url, headers=headers)

print(response.text)

# # url_input = input('Enter the URL: ')
# url_input = "https://drvikramsethi.com"
# # url = { 'url': url_input}
# # url_request = requests.post(base_url+'/urls', headers=api_key ,data=url)

# url_id = base64.urlsafe_b64encode(url_input.encode()).decode().strip("=")
# # id = url_request.json().get('data').get('id')

# # REANALYSE
# # url_id_analyse = requests.post(f'{base_url}/urls/{url_id}/analyse',headers=api_key)

# url_id_request = requests.get(f'{base_url}/urls/{url_id}',headers=api_key)

# print(url_id_request.status_code)
# print(url_id_request.text)


# GET /analyses/{id}
# GET/ip_addresses/{ip}

# # # GET /graphs
# graph_delete = requests.delete(f'{base_url}/graphs',headers=api_key)
# graph_request = requests.get(f'{base_url}/graphs',headers=api_key)
# print(graph_request.status_code)
# pprint.pprint(graph_request.text)

 # POST /graphs
# GET /graphs/{id}