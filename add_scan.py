#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Time: 2017-03-29 14:00 
# @Author  : George Wei (weichenqi@gmail.com)
# @Link    : http://weichenqi.com
# @Version : 0.1

import requests, json, datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import sys

target_ip = sys.argv[1]
mail_address = sys.argv[2]
# target_ip = 'ip1,ip2,...' 最大一个任务提交32个ip
# mail_address = 'xxx'
d1 = datetime.datetime.now()
d2 = d1 + datetime.timedelta(minutes=1)
start_time= str(d1.strftime("%Y%m%d"))+'T'+str(d2.strftime("%H%M%S"))
login_url = 'https://nessusip:8834/session'

headers = {
        "X-ApiKeys": "accessKey=*******; secretKey=*********",
        "content-type": "application/json"
}

data_scan = {
    "uuid": "731a8e52-3ea6-a291-ec0a-d2ff0619c19d7bd788d6be818b65",#说明2
    "settings": {
        "name": 'Scan-Report-SN-'+str(d1.strftime("%Y%m%d%H%M%S.%f")),
        "policy_id": "86",#说明1
        "enabled": "true",
        "emails": mail_address,
        "starttime":start_time,
        "text_targets": target_ip,
        }
}
r_get_scanid = requests.post('https://nessusip:8834/scans', data=json.dumps(data_scan), verify=False, headers=headers)
jsonres = r_get_scanid.json()
scan_id = jsonres.get('scan').get('id')
scan_file = jsonres.get('scan').get('name')
print 'Scan id is: '+str(scan_id)
print 'Scan report file name: ' +scan_file+ '.html'