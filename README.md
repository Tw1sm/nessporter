nessporter
==================
## Overview ##
Easily download entire folders of Nessus scans in the format(s) of your choosing. This script uses provided credentials to connect to a Nessus server and store a session token, which is then used for all subsquent requests.

All testing was done from Kali Linux on Nessus versions 7.0.2 and 7.0.3. 

Uses Python 2.7.

## Install ##
```bash
$ git clone https://github.com/Tw1sm/nessporter.git
$ cd nessporter
$ pip install -r requirements.txt
```

## Usage #
usage: nessporter.py [-h] -u USER [-s SERVER] [-p PORT]

```
optional arguments:
  -h, --help  show this help message and exit
  -u USER     Nessus account username
  -s SERVER   IP/name of server hosting Nessus. Defaults to 127.0.0.1
  -p PORT     port Nessus is running on. Defaults to 8834
```


