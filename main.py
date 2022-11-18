import os
import sys
from os.path import exists

# Checks if script was run with root permissions -
# Not inspired by stack overflow, not at all
#    Thanks, Dmytro
isroot = os.geteuid() == 0

if not isroot:
    sys.exit("Please run the script as root!")

fcfg = 0
def firewall_config():
    # if ufw is not installed, install it,
    # enable it, and ask for ports to allow or deny
    # then turn on logging
    
    # ufw exists, if not, install it and "recursion"
    
    fwq = input("Would you like to configure firewall (UFW) (y,n)")

    if fwq == 'n':
        pass
    elif fwq != 'y':
        print("You cant even listen to basic commands?")
        firewall_config()
        pass
        
    if exists("/bin/ufw") or exists("/usr/bin/ufw") or exists("/usr/sbin/ufw"):
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
        
        if fcfg + 1 == 1:
            print("Cant find UFW directory!")
            pass

        firewall_config()
        
    sshq = input("Would you like to allow port 22 (Check readme!) (y,n)")
    if sshq == 'y':
        os.system("sudo ufw allow 22 && sudo ufw allow ssh")
        print("Opened SSH port")
    elif sshq != 'n':
        print("Its a simple y or n question, dont answer anything else buster.")
        firewall_config()

# This should write
def lightdm_config():
    # Edit file /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    # add the following:
    # allow-guest = false
    # greeter-hide-users=true
    # greeter-show-manual-login=true
    # autologin-user=none <-- this broke our last comp image
    ldmq = input("Would you like to configure lightdm? (y,n)")
    
    if ldmq == 'n':
        pass
    elif ldmq != 'y':
        print("You cant even listen to basic commands?")
        lightdm_config()
        pass

    path = "/usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
    if exists(path):
        settings = "\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true\nautologin-user=none"
        print("Adding settings:", settings, "to", path)
        
        lightdmconf = open(path, "a")
        lightdmconf.write(settings)
        lightdmconf.close()
    else:
        print("Could not find lightdm config! Passing.")
        pass # don't know why I should have this here

def updates():
    updateq = input("Would you like to update/upgrade? (y,n)")
    if updateq == 'y':
        os.system("sudo apt update")
        print("Finished sudo apt update")
        
        os.system("sudo apt dist-updgrade")
        print("Ran sudo apt dist upgrade")
        
    elif updateq != 'n':
        print("Can you please type something that is accepted?")
        updates()

def remove_bad_apps():
    pass
    
updates()
firewall_config()    
lightdm_config()