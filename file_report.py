import requests
import os
import json


hash = input("Enter a valid SHA-256/MD5/SHA-1 Hash: ")
#e7fb23353c26aa4e715ae8ddd9a7798fb8c4777049818d6b2545eea8ebbb9044
#275a021bbfb6489e54d471899f7db9d1663fc695ec2f4725b602ad441113b2d1 
#0cbca43f0b524cd4e31efb11889c4282ef3458b94e5645aacea68e0bba285688
#f8e04c2f5b67b4e6f646de31b2ff4120456467b0ee305b322ef622b7b0c99a7f

url = f"https://www.virustotal.com/api/v3/files/{hash}"

api_key = os.getenv("VIRUSTOTAL_API_KEY")

headers = {
     "accept": "application/json",
     "x-apikey": api_key
}


response = requests.get(url, headers=headers)

if response.status_code == 200:
    print("Response status is ok!")
    try:
        data = response.json()
        with open("VirusTotalLab\\my_data.json", "w") as json_file:
            json.dump(data, json_file, indent=4)
        print("Dictionary successfully stored in my_data.json")
    except IOError as e:
        print(f"Error writing to file: {e}")

else:
    print("Response status is not ok")

#print(response.text)