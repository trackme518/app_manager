# App Manager
Web based manager to start and stop apps and commands.

## Install
Just download [latest release](https://github.com/trackme518/app_manager/releases).

## Use
Edit the `data/config.ini`, change your secret `token` (password) that is used to authenticate the user request and `port`, where the website should be served. 

Edit the `data/config.json` to add more apps. Under "app" you can list multiple commands that you want to execute. These can be .exe / .sh / .bat or other exectutables or other commands you might need. If you include `~` in the path, it will resolve it to absolute path at you user directory. You can change `config.json` during runtime. 

## Install CA certificate to avoid security warning
<p align="left">
  <img src="./assets/https_warning.png" alt="HTTPS warning" width="50%" />
</p>

Navigate to `https://127.0.0.1:9999` (replace with your port number). Click `download` and download the provided CA certificate to your remote device to prevent security warning about unsecure https / SSL connection. 

### iOS
Download .crt certfificate. Find the .cert in files, tap it. Go to Settings → General → VPN & Device Management (or Profiles) and tap the downloaded profile. Tap Install (enter passcode if prompted). Then enable trust: Settings → General → About → Certificate Trust Settings → turn ON full trust for the new CA.

### Android
Download .crt certfificate. Go to Settings->search "certificate"->CA certificate->Install anyway select your .crt file. 

## Build
Install python and create virtual environment.

* `pyenv install 3.13.12`
* `pyenv local 3.13.12`
* `pyenv rehash`
* `python -m venv venv`
* Windows
    * `venv\Scripts\activate`
* Linux / macOS
    * `source venv/bin/activate`
* `pip install -r requirements.txt`

Then you can build by:
* Windows
    * `.\build.bat`
* Linux / macOS
    * `./build.sh`

## Disclaimer
The software is provided as is. The author is not liable for any damage caused by the software. Usage of the software is completely at your own risk. 

## License
©2025 Vojtech Leischner 

Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International (CC BY-NC-SA 4.0). When using or distributing the code, give credit in the form of "App Manager software (https://github.com/trackme518/app_manager) by Vojtech Leischner (https://trackmeifyoucan.com)". Please refer to the [license](https://creativecommons.org/licenses/by-nc-sa/4.0/). For commercial licensing, please [contact](https://tricktheear.eu/contact/) us.   
