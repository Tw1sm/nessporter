#!/usr/bin/env python

################
# Created by: Matthew Creel (Tw1sm)
# Sponsored by: Schneider Downs
# Licensed under the BSD-3-Clause license
# Last Update: 04/04/2018
################

import warnings
import getpass
import argparse
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import commands
import os
import sys
import time

# get url and auth info
def getinfo():
    parser = argparse.ArgumentParser(description="used to download Nessus scans in bulk", formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('-u', type=str, dest='user', help='Nessus account username', required=True)
    parser.add_argument('-s', type=str, dest='server', help='IP/name of server hosting Nessus. Defaults to 127.0.0.1', default='127.0.0.1')
    parser.add_argument('-p', dest='port', type=str, help='port Nessus is running on. Defaults to 8834', default='8834')

    args = parser.parse_args()
    return args.server, args.port, args.user


def passw():
    print '\nNessus Authentication'
    print '---------------------'
    #user = raw_input('Username: ')
    pw = getpass.getpass('Password: ')
    print
    #return server, port, user, pw
    return pw

# list all scan folders
def listfolders(url, token):
    print '[*] Listing folders...\n'
    # requests did not work here    
    #cookies = {'X-token': token}
    #r = requests.get(url + 'folders', json=cookies, verify=False)
    #print r.text
    status, output = commands.getstatusoutput('curl -s -k -X GET -H "X-Cookie: token={}" {}folders'.format(token, url))
    folders = json.loads(output)
    # output table
    ids = []

    print '%-30s' % '+------------------------------', '%6s' % '+------+'
    print '|%-30s' % 'Folder', '|%6s|' % 'ID'

    for folder in folders['folders']:
        print '%-30s' % '+------------------------------', '%6s' % '+------+'
        print '|%-30s' % folder['name'], '|%6s|' % folder['id']
        ids.append(folder['id'])

    print '%-30s' % '+------------------------------', '%6s' % '+------+'
    return ids


# if user wants html/pdf files, ask for the chapter (report type)
def chapters():
    print
    chaps = ['Executive Summary','Vulnerablilities by Host','Vulnerabilities by Plugin']
    ids = ['1','2','3']
    print '%-30s' % '+------------------------------', '%3s' % '+---+'
    print '|%-30s' % 'Chapter', '|%3s|' % 'ID'
    for i in range(0,len(chaps)):
        print '%-30s' % '+------------------------------', '%3s' % '+---+'
        print '|%-30s' % chaps[i], '|%3s|' % ids[i]
    print '%-30s' % '+------------------------------', '%3s' % '+---+'
    
    chap = ''
    while True:    
        chap = raw_input('\nEnter the ID of the chapter you want to download: ')
        if chap == '1':
            path = ', "chapters": "vuln_hosts_summary"'
            break
        elif chap == '2':     
            path = ', "chapters": "vuln_by_host"'
            break
        elif chap == '3':     
            path = ', "chapters": "vuln_by_plugin"'
            break
        else:
            print 'Invalid chapter. Try again.'
    return path
    

# get folder to save files in
def getsavepath():
    while True:
        path = raw_input('\nEnter the path of the directory you want to save the reports in: ')
        confirm = raw_input('Are you sure you want to save the reports in {}? (Y/N): '.format(path))
        if confirm.lower() == 'y':
            if not os.path.isdir(path):
                os.mkdir(path)
             
            return path
    

# get the id of the folder user wants to download, file format, + chapter if necessary
def getid(ids):
    ftypes = []
    while True:
        folder = raw_input('\nEnter the ID number of the folder you want to download (\'Done\' to logout): ')
        if folder.lower() != 'done':
            if int(folder) in ids:
                confirm = raw_input('Are you sure you want to download scans from folder ID {} (Y/N): '.format(folder))
                if confirm.lower() == 'y':
                    while True:
                        ftype = raw_input('\nSelect a file format to save as (\'nessus\', \'pdf\', \'html\', \'csv\', or \'all\'): ')
                        if ftype.lower() in {'pdf','nessus','html','csv', 'all'}:
                            if ftype.lower() == 'all':
                                ftypes = ['pdf','nessus','html','csv']
                            else:
                                ftypes.append(ftype)
                            
                            if 'pdf' in ftypes or 'html' in ftypes:                            	
				                chap = chapters()
                            else:
				                chap = ''
				                
                            break
                        else:
                            print 'Invalid file type. Try again.'
                    return folder, ftypes, chap
            else:
                print 'Invalid ID. Try again.'
        else:
            break


# perform file download
def download(url, token, scanid, filetoken, scanname, ftype, savepath):
    while True:
        status, output = commands.getstatusoutput('curl -s -k -X GET -H "X-Cookie: token={}" -H "Content-Type: application/json" {}scans/{}/export/{}/status'.format(token, url, scanid, filetoken))
        statusjson = json.loads(output)
        downloadstatus = statusjson['status']
        if downloadstatus == 'ready':
            print '[*] Saving report - {}.{}'.format(scanname, ftype)
            status, output = commands.getstatusoutput('curl -s -k -X GET -H "X-Cookie: token={}" -H "Content-Type: application/json" {}scans/{}/export/{}/download -o "{}/{}.{}"'.format(token, url, scanid, filetoken, savepath, scanname, ftype))
            break


# get all scans for selected folder and prepare info needed for download                
def getscans(url, token, folder, ftypes, chap, savepath):
    print
    
    # pull data for every scan
    status, output = commands.getstatusoutput('curl -s -k -X GET -H "X-Cookie: token={}" {}scans'.format(token, url))
    allscans = json.loads(output)
    scans = []
    
    try:
        # search for scans only in the specified folder
        for scan in allscans['scans']:
            if scan['folder_id'] == int(folder):
                scans.append(scan)
            
        # for all relevant scans
        for scan in scans:
            histids = []
            histstatuses = []
            scanid = scan['id']
            
            # individual scan data
            status, output = commands.getstatusoutput('curl -s -k -X GET -H "X-Cookie: token={}" {}scans/{}'.format(token, url, scanid))
            scandata = json.loads(output)

            # check scan history (may be more than 1 [cancels, aborts])
            for hist in scandata['history']:
                histstatuses.append(hist['status'])
                histids.append(hist['history_id'])

            for ftype in ftypes:
                if ftype in {'pdf','html'}:   
                    fmat = '\'{{"format": "{}"{}}}\''.format(ftype, chap)
                else:
                    fmat = '\'{{"format": "{}"}}\''.format(ftype)
                curlcmd = 'curl -s -k -X POST -H "X-Cookie: token={}" -H "Content-Type: application/json" -d {} {}scans/{}/export?history_id={}'.format(token, fmat, url, scanid, histids[0])
                
                # if only 1 scan in history, download as long as not canceled    
                if len(histids) == 1 and histstatuses[0] != 'canceled':
                    status, output = commands.getstatusoutput(curlcmd)
                    filejson = json.loads(output)
                    filetoken = filejson['file']
                    download(url, token, scanid, filetoken, scan['name'], ftype, savepath)
                else:
                    iscomplete = False
                    # if more than 1 scan in history, search for one that is complete
                    for status in histstatuses:
                        if status == 'completed':
                            iscomplete = True
                            status, output = commands.getstatusoutput(curlcmd)
                            filejson = json.loads(output)
                            filetoken = filejson['file']
                            download(url, token, scanid, filetoken, scan['name'], ftype, savepath)
                    if not iscomplete:
                        # if no scan in history is complete, download aborted scan if available
                        for status in histstatuses:
                            if status == 'aborted':
                                status, output = commands.getstatusoutput(curlcmd)
                                filejson = json.loads(output)
                                filetoken = filejson['file']
                                download(url, token, scanid, filetoken, scan['name'], ftype, savepath)
    except TypeError:
        print '[!] No scans found in folder...'  


def banner():
    print'''
    
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

    '''
    time.sleep(0.5)


def main():
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
    url = ''
    token = ''

    server, port, user = getinfo()
    banner()    

    while True:
        try:
            pw = passw()
        except:
            print '\n\n[!] Exiting.. '
            sys.exit()
    
        #login    
        url = 'https://{}:{}/'.format(server, port)
        payload = {'username':user, 'password':pw}       
        headers = {'Content-Type':'application/json'}
        print '[*] Attempting login at {}'.format(url)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            try:      
                r = requests.post(url + 'session', headers=headers, json=payload, verify=False)
                parsed = json.loads(r.text)
                if parsed.keys()[0] == 'token':        
                    token = parsed['token']
                    break
                elif parsed['error']:        
                    print '[!] Login attempt failed: {}'.format(parsed['error'])    
            except Exception, e:
                print '[!] Error attempting connection:'            
                print '\t{}\n'.format(e)
                sys.exit()        

    ids = listfolders(url, token)
    
    while True:
        try:
            folder, ftypes, chap = getid(ids)
            savepath = getsavepath()
        except KeyboardInterrupt:
            print '\n\n[!] Logged out'
            break
        except:
            print '\n[!] Logged out'
            break
            
        #get scans in folder
        getscans(url, token, folder, ftypes, chap, savepath)


if __name__ == '__main__':
    main()
