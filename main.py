import os
import sys
from os.path import exists

def firewall_config():
    # if ufw is not installed, install it,
    # enable it, and ask for ports to allow or deny
    # then turn on logging
    
    # ufw exists, if not, install it and "recursion"
    if exists("/bin/ufw") or exists("/usr/bin/ufw"):
        print("UFW exists, configuring..")
        
        os.system("sudo ufw enable")
        print("Enabled UFW")
        
        os.system("sudo ufw logging full")
        print("Enabled full logging for UFW")

        notdone = True
        while notdone:
            portsq = input("Would you like to deny/allow ports? (y,n)")
            if portsq.lower() == 'y':
                port = input("What port would you like to allow? (type 'n' for none)")
                
                if port.isnumeric():
                    os.system("sudo ufw allow " + port)
                    print("Allowed port: " + port)
                elif port == "n":
                    # ask for deny
                    port = input("What ports would you like to deny? (type 'n' for none)")
                    if port.isnumeric():
                        os.system("sudo ufw deny " + port)
                        print("Blocked port: " + port)
                    elif port == "n":
                        notdone = False
                        break
                    else:
                        print("No port config because you cant do something simple!")
                        notdone = False
                        break
                else:
                    print("No port config because you cant do something simple!")
                    notdone = False
                    break
            elif portsq.lower() == 'n':
                notdone = False
                break
            else:
                print("No port conifg because you cant do something simple!")
                notdone = False
                break
    else:
        print("UFW is not installed, installing it...") 
        os.system("sudo apt install ufw") 
        print("UFW should be installed?")

        firewall_config()
    