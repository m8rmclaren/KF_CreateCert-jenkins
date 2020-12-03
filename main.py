"""
* FILE: main.py
* PROJECT: Enroll and Deploy Certificate with KF
* PURPOSE: Use Python requests library and data as arguments to enroll certificate in Keyfactor
* AUTHOR: Hayden Roszell
* HISTORY: Version 1.9 12/1/2020
*
* Copyright © 2020 Keyfactor. All rights reserved.
"""

import requests
import datetime
import json
import sys
import socket


class Config:
    def __init__(self):
        self.cert_data = {}
        self.cert_data_lst = []
        self.meta_data = {}
        self.meta_data_lst = []
        with open("config.json", 'r') as datafile:
            self.serial = json.load(datafile)  # open configuration file

        # Get script arguments
        for i in range(len(sys.argv) - 1):
            self.cert_data_lst.append(sys.argv[i + 1])  # read in script arguments
        self.script_args = ["KFStoreID", "CommonName", "CertFormat", "Password", "CertAlias", "Email"]  # define arguments for dict
        self.zipped_cert_data = zip(self.script_args, self.cert_data_lst)  # create iterator for tuples
        for field, data in self.zipped_cert_data:
            self.cert_data[field] = data  # create dict of arguments

        # Get metadata, same methods as above
        self.meta_data_lst.append(socket.gethostname())
        self.meta_data_lst.append([l for l in (
            [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")][:1], [
                [(s.connect(('8.8.8.8', 53)), s.getsockname()[0], s.close()) for s in
                 [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1]]) if l][0][0])
        self.metadata_fields = ["Hostname", "IP"]
        self.zipped_metadata = zip(self.metadata_fields, self.meta_data_lst)
        for field, data in self.zipped_metadata:
            self.meta_data[field] = data
        return

    def get_store_type(self):
        if self.cert_data["CertFormat"] == "JKS":
            return 0
        elif self.cert_data["CertFormat"] == "PEM":
            return 2


class Output:
    def __init__(self):
        self.cert_id = int
        self.request_id = int
        self.output_json = {json}
        self.pfx_data = {}
        self.log_text = str
        self.log_file = "log.txt"
        self.output_file = "output.json"
        self.timestamp = str

    def get_timestamp(self):
        self.timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    def write_to_file(self, option):
        timestamp = str(self.timestamp) + ": "
        if option == 1:
            write = timestamp + str(self.log_text)
            f = open(self.log_file, 'a')
        else:
            write = str(self.output_json)
            f = open(self.output_file, 'a')
        f.write(write + '\n')
        f.close()
        return

    def get_cert_id(self, r):
        json_response = json.loads(json.dumps(r.json()))
        self.request_id = (json_response['CertificateInformation']['KeyfactorRequestId'])
        self.cert_id = (json_response['CertificateInformation']['KeyfactorId'])
        self.pfx_data = json_response

    def evaluate(self, r):
        if r.status_code == 200:
            self.log_text = "API call succeeded with status code " + str(r.status_code) + " OK"
            self.write_to_file(1)
        else:
            self.log_text = "API call failed with status code " + str(r.status_code)
            self.write_to_file(1)
            sys.exit(9)

    def pack_output(self):
        output_fields = ["CertID", "RequestID", "SerialNumber", "IssuerDN", "Thumbprint"]
        output_data = {}
        output_data_lst = [self.cert_id, self.request_id,
                           self.pfx_data["CertificateInformation"]["SerialNumber"],
                           self.pfx_data["CertificateInformation"]["IssuerDN"],
                           self.pfx_data["CertificateInformation"]["Thumbprint"]]
        zipped_output = zip(output_fields, output_data_lst)
        for field, data in zipped_output:
            output_data[field] = data
        self.output_json = json.dumps(output_data)
        self.write_to_file(2)


def enroll_pfx(output):
    config = Config()
    headers = {'authorization': config.serial["Auth"]["APIAuthorization"],
               'x-keyfactor-appkey': config.serial["Auth"]["APIKey"],
               'Content-Type': 'application/json', 'Accept': 'application/json',
               'x-keyfactor-requested-with': 'APIClient', 'x-certificateformat': 'STORE'}
    output.get_timestamp()
    body = {
        "Subject": "cn=" + config.cert_data["CommonName"],
        "CertificateAuthority": config.serial["Misc"]["CertificateAuthority"],
        "Password": config.cert_data["Password"],
        "Metadata": {
            "Email-Contact": config.cert_data["Email"],
            "Hostname": config.meta_data["Hostname"],
            "IP": config.meta_data["IP"]
        },
        "Timestamp": output.timestamp,
        "Template": config.serial["Misc"]["CertificateTemplate"],
        "SANs": {
            "DNS": [
                config.cert_data["CommonName"]
            ]
        }
    }
    r = requests.post(config.serial["URL"]["EnrollURL"], headers=headers, json=body)
    output.evaluate(r)
    output.get_cert_id(r)
    return


def deploy_pfx(output):
    config = Config()
    headers = {'authorization': config.serial["Auth"]["APIAuthorization"], 'Content-Type': 'application/json',
               'Accept': 'application/json', 'x-keyfactor-requested-with': 'APIClient',
               'x-certificateformat': config.cert_data["CertFormat"]}
    output.get_timestamp()
    body = {
        "StoreIds": [
            config.cert_data["KFStoreID"]
        ],
        "StoreTypes": [
            {
                "StoreTypeId": config.get_store_type(),
                "Alias": config.cert_data["CertAlias"],
                "Overwrite": "true",
                "Properties": []
            }
        ],
        "CertificateId": output.cert_id,
        "RequestId": output.request_id,
        "Password": config.cert_data["Password"],
        "JobTime": output.timestamp
    }
    r = requests.post(config.serial["URL"]["DeployURL"], headers=headers, json=body)
    output.evaluate(r)
    return


def main():
    output = Output()
    enroll_pfx(output)
    deploy_pfx(output)

    output.pack_output()


main()


# Script args: "StoreID" "CommonName", "CertFormat", "Password", "CertAlias", "Email"
