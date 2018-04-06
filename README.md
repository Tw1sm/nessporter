nessporter
==================
## Overview ##
Easily download entire folders of Nessus scans in the format(s) of your choosing. This script uses provided credentials to connect to a Nessus server and store a session token, which is then used for all subsquent requests.

All testing was done from Kali Linux on Nessus versions 7.0.2 and 7.0.3. 

Uses Python 2.7.

```
 ____     ___  _____ _____ ____    ___   ____  ______    ___  ____  
|    \   /  _]/ ___// ___/|    \  /   \ |    \|      T  /  _]|    \ 
|  _  Y /  [_(   \_(   \_ |  o  )Y     Y|  D  )      | /  [_ |  D  )
|  |  |Y    _]\__  T\__  T|   _/ |  O  ||    /l_j  l_jY    _]|    / 
|  |  ||   [_ /  \ |/  \ ||  |   |     ||    \  |  |  |   [_ |    \ 
|  |  ||     T\    |\    ||  |   l     !|  .  Y |  |  |     T|  .  Y
l__j__jl_____j \___j \___jl__j    \___/ l__j\_j l__j  l_____jl__j\_j
                                                                   
    
                  Created By: Matthew Creel (Tw1sm)
                    Sponsored By: Schneider Downs
               Homepage: https://www.schneiderdowns.com

    
Nessus Authentication
---------------------
Password: 
```

```
[*] Attempting login at https://127.0.0.1:8834/
[*] Listing folders...

+------------------------------ +------+
|Folder                         |    ID|
+------------------------------ +------+
|Trash                          |     2|
+------------------------------ +------+
|My Scans                       |     3|
+------------------------------ +------+
|Testing                        |     4|
+------------------------------ +------+
|Client 1                       |     8|
+------------------------------ +------+
|Client 2                       |     9|
+------------------------------ +------+
|Client 3                       |    10|
+------------------------------ +------+

Enter the ID number of the folder you want to download ('Done' to logout): 10
Are you sure you want to download scans from folder ID 10 (Y/N): y

Select a file format to save as ('nessus', 'pdf', 'html', 'csv', or 'all'):
```

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

Example connect to Nessus on local system:
```bash
$ python nessporter.py -u Tw1sm
```
Example of connection to Nessus on remote system:
```bash
$ python nessporter.py -u Tw1sm -s 192.168.109.132
```

