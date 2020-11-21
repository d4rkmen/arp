[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)  [![Gitter](https://badges.gitter.im/cesanta/mongoose-os.svg)](https://gitter.im/cesanta/mongoose-os?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)

# Address Resolution Protocol lib for Mongoose OS

It helps to discover local network devices (IP and MAC address)

## Supported platforms

* `ESP8266`
* `ESP32`

## Comfig schema

```javascript
"arp": {
  "rpc_enable": true      // Enable ARP RPC handler
}
```
## RPC

```javascript
$ mos call --port ws://192.168.1.216/rpc ARP.Scan
[
	{
		"ip": "192.168.1.72",
		"mac": "ee:d7:22:9a:eb:6b"
	},
	{
		"ip": "192.168.1.88",
		"mac": "00:a0:96:59:5e:83"
	},
	{
		"ip": "192.168.1.112",
		"mac": "ba:c5:57:5b:49:b6"
	},
	{
		"ip": "192.168.1.136",
		"mac": "92:14:b1:03:9c:e4"
	},
	{
		"ip": "192.168.1.165",
		"mac": "c0:48:e6:7a:84:ae"
	},
	{
		"ip": "192.168.1.167",
		"mac": "00:c2:c6:d0:76:a4"
	},
	{
		"ip": "192.168.1.172",
		"mac": "90:dd:5d:f0:03:b7"
	},
	{
		"ip": "192.168.1.181",
		"mac": "00:c2:c6:d0:76:a4"
	},
	{
		"ip": "192.168.1.195",
		"mac": "5c:e5:0c:dc:16:d9"
	},
	{
		"ip": "192.168.1.222",
		"mac": "00:17:9a:62:87:6c"
	}
]
```

## Known issues

`ESP8266` precompiled LWIP has 10 items only