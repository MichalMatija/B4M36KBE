# Blockchain

## 1. Step (find difference)
Firstly, I found difference between webpage in assignment and real page https://www.bitaddress.org. 
I compared both the source codes of pages where I used the following website for this purpose. https://www.diffchecker.com
Below in the image, we can see the difference.
![comparison of two html pages](comparison%20of%20two%20html%20pages.jpg)

## 2. Step (create key)  
According to the image from the first step, we know that number of all keys is **3,000** because each random number from function ```ECDSA.getBigRandom(n)``` uses module 3,000.
Therefore I changed the source code from the assignment and generate all 3,000 public addresses and private keys.
```javascript
generateNewAddressAndKey: function () {
    try {
        var my_array = []
		for (let i = 0; i < 3000; i++) {
		    my_array[i] = new BigInteger(i.toString()).multiply(new BigInteger("424242424242424244242424244242424242424"))
				.add(new BigInteger("SoLongAndThanksForAllTheFish"));
		    var my_key = new Bitcoin.ECKey(false, my_array[i]);
		    my_key.setCompressed(true);
		    var my_bitcoinAddress = my_key.getBitcoinAddress();
		    var my_privateKeyWif = my_key.getBitcoinWalletImportFormat();
		    console.log("[" + i + "] " + my_array[i].toString() + ", " + my_bitcoinAddress + ", " + my_privateKeyWif);
	    }
		var key = new Bitcoin.ECKey(false);
		console.log(key.getBitcoinPrivateKeyByteArray().toString())
		key.setCompressed(true);
		var bitcoinAddress = key.getBitcoinAddress();
		console.log(bitcoinAddress.toString())
		var privateKeyWif = key.getBitcoinWalletImportFormat();
		console.log(privateKeyWif.toString())
		document.getElementById("btcaddress").innerHTML = bitcoinAddress;
		document.getElementById("btcprivwif").innerHTML = privateKeyWif;
		var keyValuePair = {
		    "qrcode_public": bitcoinAddress,
			"qrcode_private": privateKeyWif
		};
		qrCode.showQrCode(keyValuePair, 4);
	}
	catch (e) {
		// browser does not have sufficient JavaScript support to generate a bitcoin address
		alert(e);
		document.getElementById("btcaddress").innerHTML = "error";
		document.getElementById("btcprivwif").innerHTML = "error";
		document.getElementById("qrcode_public").innerHTML = "";
		document.getElementById("qrcode_private").innerHTML = "";
	}
}
```

The generated values are stored in this [csv file](addressesAndPrivateKeys.csv)

## 3. Step (find wallet)
I used Blockchain API for finding the number of transaction by address. The following url base address was used ```https://blockchain.info/multiaddr?active=```. 
Example of full url ```https://blockchain.info/multiaddr?active=19Rn11MzzrVKh76ne5qEuCyQDNtWzoH8Bh%7C13ra3h6M45ETbgAXrYccMWywjUwztDpZcG```. In [blockchain.py](blockchain.py) is code which calls blockchain API and checks if exist some transactions.

_Comparison of two files_: https://www.diffchecker.com  
_Blockchain API_: https://www.blockchain.com/api/blockchain_api  
_Generated public addresses and private keys_: [addressesAndPrivateKeys.csv](addressesAndPrivateKeys.csv)  
_Modified source code of webpage_: [bitaddress.org.html](bitaddress.org.html)  
_Information about all generated addresses_: [addressesInfo.csv](addressesInfo.csv)

**Public address**: 1E2mSN7MXVuS4ecafhTLtaokf5RixcYUEU  
**Private key**: KwDiBf89QgGbjEhKnhXJuY4GUMKjkbiQLBXrUaWStqmWnp3XBMte  
**Wallet**: https://www.blockchain.com/btc/address/1E2mSN7MXVuS4ecafhTLtaokf5RixcYUEU
