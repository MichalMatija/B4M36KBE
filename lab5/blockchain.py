import csv
import time
from json import loads
import requests as req

url_param_values = ""

with open('addressesAndPrivateKeys.csv') as file:
    csv_reader = csv.reader(file)
    index = 0
    header = True

    for row in csv_reader:
        if header:
            header = False
            continue
        # Join together every 30 addresses for API calls
        if index == 30:
            index = 0
            url_param_values += '\n'
        if index == 0:
            url_param_values += row[2]
        # %7C is delimiter of two addresses
        else:
            url_param_values += "%7C" + row[2]
        index += 1

# save helper file
with open('blockchainUrl.txt', 'w') as file:
    file.write(url_param_values)

address_base = "https://blockchain.info/multiaddr?active="
addresses_info = []
with open('blockchainUrl.txt', 'r') as f:
    data = f.read().split("\n")
    for param_value in data:
        response = req.get(address_base + param_value)
        addresses = loads(response.content)
        for address in addresses['addresses']:
            address_info_tuple = (address['address'], address['n_tx'], address['final_balance'],
                                  address['total_received'], address['total_sent'])
            if address['n_tx'] != 0:
                print(address['address'])
            addresses_info.append(address_info_tuple)
        print(addresses)
        # Blockchain API can ban me if I call several times their API per second or few seconds
        time.sleep(5)

    # print(data)

with open('addressesInfo.csv', 'w') as file:
    columns = ['Address', 'Number of transactions', 'final_balance', 'total_received', 'total_sent']
    writer = csv.DictWriter(file, fieldnames=columns)

    writer.writeheader()
    for address_info in addresses_info:
        writer.writerow({'Address': address_info[0], 'Number of transactions': address_info[1],
                         'final_balance': address_info[2], 'total_received': address_info[3],
                         'total_sent': address_info[4]})
