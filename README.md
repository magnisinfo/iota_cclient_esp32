# IOTA CClient simple wallet on ESP32

This project based on example project [IOTA CClient example on ESP32](https://github.com/oopsmonk/iota_cclient_esp32).

## Requirement  

* xtensa-esp32 toolchain
* ESP-IDF v3.2.2

To get the toolchain and ESP-IDF, please reference [esp-idf with CMake](https://docs.espressif.com/projects/esp-idf/en/latest/get-started-cmake/index.html#installation-step-by-step).

## Install ESP32 build system  

* [xtensa-esp32 toolchain](https://docs.espressif.com/projects/esp-idf/en/stable/get-started/linux-setup.html) setup  
* [ESP-IDF](https://docs.espressif.com/projects/esp-idf/en/v3.2.2/get-started/index.html#get-esp-idf) setup

## Build and flash to ESP32

### Step 1: checkout source  

```
git clone --recursive https://github.com/magnisinfo/iota_cclient_esp32
cd iota_cclient_esp32
git checkout iota_simple_wallet
```

### Step 2: Init components

```
cd iota_cclient_esp32
bash ./init.sh
```

### Step 3: Configure 

```
#Run this command:
./config 
#or run file "config"

# configure WiFi SSID & Password
[IOTA CClient Configuration] -> [WiFi SSID]
[IOTA CClient Configuration] -> [WiFi Password]
[IOTA CClient Configuration] -> [IRI Node URI]
[IOTA CClient Configuration] -> [Port Number of IRI Node]
```

### Step 4: Build & flash

```
#Run this command:
./flash 
#or run file "flash"

#After build choose flash port:
Choose port to load:
(1) - /dev/cu.Bluetooth-Incoming-Port
(2) - /dev/cu.SLAB_USBtoUART
Write number:
2
```

output:  
```
I (10454) wifi: pm start, type: 1

I (11604) tcpip_adapter: sta ip: 192.168.43.10, mask: 255.255.255.0, gw: 192.168.43.1
I (11604) iota_main: Connected to AP
I (11604) iota_main: IRI Node: nodes.devnet.thetangle.org, port: 443, HTTPS:True

Welcome to IOTA wallet. Write you seed:
>999999999999999999999999999999999999999999999999999999999999999999999999999999999

Choose operation:
(1)-Get account balance
(2)-Send tokens to address
(3)-Send message
>
```
