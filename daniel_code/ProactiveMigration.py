from typing import List, Dict
import paramiko 
import logging
from scp import SCPClient
from subprocess import Popen
import yaml
from pprint import pprint
import random
import time
from timeloop import Timeloop
from datetime import timedelta


from os.path import isfile
tl = Timeloop()

#Controller will know "Current Host" by calling a get Function from the Migrator class

class Migrator:
    def __init__(self,):

        self.current_host = "vm1"  # Let's always upon boot start at vm1

        self.yaml_file = None
        self.vm_pool_list:list = None
        self.vms:dict = None  # {vm_name :{VM_INFO}}
        self.key_cred:dict = None
        self.dummy_vm = None


        with open("./hosts.yaml", 'r') as file:
            yaml_file = yaml.safe_load(file)
            self.yaml_file = yaml_file
        
            self.key_cred = yaml_file["key_cred"]
            self.vm_pool_list = yaml_file["vm_pool"]
            self.vms = yaml_file["vms"]
            self.dummy_vm = yaml_file["Dummy_VM"]
        
        # for attribute, value in self.__dict__.items():
        #     print(attribute, value)

    def chooseNextVM(self)->str:   #Destination of next VM to migrate to
        prev_host = self.current_host
        next_host = random.choice(self.vm_pool_list)
        while(next_host == self.current_host):
            next_host = random.choice(self.vm_pool_list)
        #print("Previous Host {} ----> Next Host {}".format(prev_host, next_host))
        return next_host
    
    def getClient(self, host_dict):
        client = paramiko.SSHClient()
        key = paramiko.RSAKey.from_private_key_file( filename = self.key_cred["controller_rsa_ssh_key_path"],password= str(self.key_cred["passphrase"]))
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        #client.connect(hostname= host2["host"],pkey=key ,username=host2["user"], port=25613)

        client.connect( hostname=host_dict["host"],username=host_dict["user"], pkey = key,
                        port=host_dict["port"],
                        )
        return client   #client.close()
    
    @tl.job(interval = timedelta(seconds=30))
    def migrate(self,): # Host Source, Host Destination
        """
        1) SSH to current host
        2) Run pscp command to migrate
        3) Delete File
        4) Close connection
        """
        current_vm_host_name = self.current_host
        current_vm_info = self.vms[self.current_host]

        # next_vm_host_name = self.chooseNextVM()
        next_vm_host_name = "vm2"
        next_vm_info = self.vms[next_vm_host_name]
        print("Migrating from {} ----> {}".format(current_vm_host_name, next_vm_host_name))
        print("Previous Host {} ----> Next Host {}".format(current_vm_info, next_vm_info ))

        print(isfile(self.key_cred["putty_key"]))
        print(isfile(self.key_cred["controller_rsa_ssh_key_path"]))
    
        file_path = "/var/www/html/test.txt"  # Local and Target host file path because they share the same paths
        host_dst = "{user}@{host}:{path}".format(user=next_vm_info["user"], host=next_vm_info["host"],path=file_path)
        #pscp -batch -i /users/daniel05/.ssh/id_geni_ssh_rsa.ppk -pw 12345 -P 25014 /var/www/html/test.txt daniel05@pc1.geni.it.cornell.edu:/var/www/html/test.txt
        pscp_command = "pscp -batch -i {ppk_key} -pw {passphrase} -P {dst_port} {source} {host_dst}".format(
            ppk_key = self.key_cred["putty_key"],
            passphrase = self.key_cred["passphrase"],
            dst_port = next_vm_info["port"],
            source = file_path,
            host_dst = host_dst

        )
        



        host_client = self.getClient(current_vm_info)
        self.execute_commands(host_client,[pscp_command])

        # rm_command =f"""sudo rm /var/www/html/video1.mp4"""
        # commands = [
        #     "cd ../../",
        #     "ls"
        #     # scp_command, 
        #     # key_cred["passphrase"],
        #     #rm_command
        # ]
        # execute_commands(host_src_client, commands=commands)
        # host_src_client.close()  #Close the client
        print("Migrated From {} ---> {}".format(current_vm_host_name, next_vm_host_name))

        self.current_host = next_vm_host_name
        return (next_vm_host_name, next_vm_info)

    def execute_commands(self,client, commands: List[str]):
        
        for cmd in commands:
            stdin, stdout, stderr = client.exec_command(cmd)
            stdout.channel.recv_exit_status()
            response = stdout.readlines()
            for line in response:
                print(
                    f"INPUT: {cmd}\n \
                    OUTPUT: {line}"
                )

    def getCurrentHost(self):
        return self.current_host




migrator = Migrator()
migrator.migrate()


# print(isfile("/c/Users/danie/.ssh/test.txt"))
# print(isfile("C:/Users/danie/.ssh/id_geni_ssh_rsa"))


# /var/www/html/




# migrator = Migrator()
# for i in range(10):
#     migrator.migrate()


#migrate(host_src=vm1, host_dst=vm2)

# client = getClient(vm1)
# stdin, stdout, stderr = client.exec_command("pscp -batch -i /users/daniel05/.ssh/id_geni_ssh_rsa.ppk -pw 12345 -P 25014 /var/www/html/test.txt daniel05@pc1.geni.it.cornell.edu:/var/www/html/test.txt")
# print(stdout.read())
# client.close()




# client = paramiko.client.SSHClient()
# client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
# client.connect(host, username=username, password=password)
# _stdin, _stdout,_stderr = client.exec_command("df")
# print(_stdout.read().decode())
# client.close()  # close client

