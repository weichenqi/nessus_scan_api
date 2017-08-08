#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Time: 2017-03- 13:23 
# @Author  : George Wei (weichenqi@gmail.com)
# @Link    : http://weichenqi.com
# @Version :
import requests, json, sys, os, getpass, time, requests.packages.urllib3
requests.packages.urllib3.disable_warnings()

url = 'https://nessusip:8834'
verify = False
token = ''
Lusername = 'u' #填入
Lpassword = 'p' #填入

def build_url(resource):
        return '{0}{1}'.format(url, resource)


def connect(method, resource, data=None):
        headers = {'X-Cookie': 'token={0}'.format(token), 'content-type': 'application/json'}
        data = json.dumps(data)
        if method == 'POST':
                r = requests.post(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'PUT':
                r = requests.put(build_url(resource), data=data, headers=headers, verify=verify)
        elif method == 'DELETE':
                r = requests.delete(build_url(resource), data=data, headers=headers, verify=verify)
                return r.status_code
        else:
                r = requests.get(build_url(resource), params=data, headers=headers, verify=verify)

        if r.status_code != 200:
                e = r.json()
                print e['error']
                sys.exit()

        if 'download' in resource:
                return r.content
        else:
                return r.json()

def login(usr, pwd):
        login = {'username': usr, 'password': pwd}
        data = connect('POST', '/session', data=login)
        return data['token']

def logout():
        connect('DELETE', '/session')


def list_scan():
        data = connect('GET', '/scans')
        return data

def count_scan(scans, folder_id):
        count = 0
        for scan in scans:
                if scan['folder_id']==folder_id: count=count+1
        return count

def print_scans(data, folder_name = 'all'):
        if folder_name == 'All' or folder_name == 'all':
                for folder in data['folders']:
                        print("\\{0} - ({1})\\".format(folder['name'], count_scan(data['scans'], folder['id'])))
                        for scan in data['scans']:
                                if scan['folder_id'] == folder['id']:
                                        print("\t\"{0}\" - uuid: {1}".format(scan['name'].encode('utf-8'), scan['uuid']))
        else:
                folder_id = get_folder_id(folder_name, data)
                if count_scan(data['scans'], folder_id) == 0:
                        print("\\{0} - Folder is empty\\".format(folder_name))
                        return
                if folder_id != 0:
                        print("\\{0} - ({1})\\".format(folder_name, count_scan(data['scans'], folder_id)))
                        for scan in data['scans']:
                                if scan['folder_id'] == folder_id:
                                         print("\t\"{0}\"".format(scan['name'].encode('utf-8')))
                else:
                        print("{0} folder not found".format(folder_name))

def export_status(scan_id, file_id):
        data = connect('GET', '/scans/{0}/export/{1}/status'.format(scan_id, file_id))
        return data['status'] == 'ready'

def get_folder_id(serch_folder_name, data):
        folder_id = 0
        for folder in data['folders']:
                if folder['name'] == serch_folder_name:
                        folder_id = folder['id']
                        break
        return folder_id

def export_folder(data, folder_name = 'all'):
        if folder_name == 'All' or folder_name == 'all':
                for scan in data['scans']:
                        file_id = export(scan['id'])
                        download(scan['name'], scan['id'], file_id, os.path.join(os.getcwd(), folder_name))
        else:
                folder_id = get_folder_id(folder_name, data)
                if count_scan(data['scans'], folder_id) == 0:
                        print "Reports to download is missing"
                        return
                if folder_id != 0:
                        for scan in data['scans']:
                                if scan['folder_id'] == folder_id:
                                        file_id = export(scan['id'])
                                        download(scan['name'], scan['id'], file_id, os.path.join(os.getcwd(), folder_name))

                else:
                        print("{0} folder not found".format(folder_name))

def get_last_history_index(history):
        count = 0
        for hist in history:
                count=count+1
        return count-1

def get_last_history(scan_id):
        data = connect('GET', '/scans/{0}'.format(scan_id))
        return data['history'][get_last_history_index(data['history'])]['history_id']

def export(scan_id):
        data = {"format":"html", "chapters":"vuln_by_host", "history_id": "{0}".format(get_last_history(scan_id))}
        data = connect('POST', '/scans/{0}/export'.format(scan_id), data=data)
        file_id = data['file']
        while export_status(scan_id, file_id) is False:
                time.sleep(5)
        return file_id

def download(report_name, scan_id, file_id, save_path):
        save_path = 'static'
        if not(os.path.exists(save_path)): os.mkdir(save_path)
        data = connect('GET', '/scans/{0}/export/{1}/download'.format(scan_id, file_id))
        file_name = '{0}.html'.format(report_name.encode('utf-8'))

        print('Saving report to {0}/{1}'.format(save_path, file_name))
        with open(os.path.join(save_path, file_name.replace('\t','')), 'w') as f:
                f.write(data)
        del_scan(scan_id)

def del_scan(scan_id):
        print "Deleteing scan task {0}...".format(scan_id)
        connect('DELETE', '/scans/{0}'.format(scan_id))


print("Login...")
username = Lusername
password = Lpassword

token = login(username, password)

print("List of reports...")
rep_list = list_scan()
if str(rep_list.get('scans')) == 'None':
        print "No scan task"
        sys.exit()
else:
        print_scans(rep_list)
        print("Exporting reports...")
        export_folder(rep_list, 'all')
logout()