BLE Scanner for the Raspberry Pi. To install: 

- Clone in folder /home/pi/src/cairo-blescanner-rpi/ or change the folder in service.sh
- If you don't have bluez installed, run: 'sh install_bluez.sh'
- If you want the scanner to run when the RPI boots, install it as a service by running: 'sh install_service.sh'

Logs will go to /var/log/cairo-blescanner.log, each line is a JSON document representing a Nearable packet.