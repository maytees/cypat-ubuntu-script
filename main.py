import os
import sys
from os.path import exists

class bordercolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
def err(msg):
    print(bordercolors.FAIL + msg + bordercolors.ENDC)

def warn(msg):
    print(bordercolors.WARNING + msg + bordercolors.ENDC)

def log(msg):
    print(bordercolors.OKCYAN + msg + bordercolors.ENDC)

def question(q):
    return bordercolors.OKGREEN + q + bordercolors.ENDC + '\n'
    
# Checks if script was run with root permissions -
# Not inspired by stack overflow, not at all
#    Thanks, Dmytro
isroot = os.geteuid() == 0

if not isroot:
    sys.exit("Please run the script as root!")

warn("Please make sure that you read the readme before running this!")
 
fcfg = 0
def firewall_config():
    # if ufw is not installed, install it,
    # enable it, and ask for ports to allow or deny
    # then turn on logging
    
    # ufw exists, if not, install it and "recursion"
    
    fwq = input(question("Would you like to configure firewall (UFW) (y,n)"))

    if fwq == 'n':
        return
    elif fwq != 'y':
        err("You cant even listen to basic commands?")
        firewall_config()
        return
        
    if exists("/bin/ufw") or exists("/usr/bin/ufw") or exists("/usr/sbin/ufw"):
        log("UFW exists, configuring..")
        
        os.system("sudo ufw enable")
        log("Enabled UFW")
        
        os.system("sudo ufw logging full")
        log("Enabled full logging for UFW")

        notdone = True
        while notdone:
            portsq = input(question("Would you like to deny/allow ports? (y,n)"))
            if portsq.lower() == 'y':
                port = input(question("What port would you like to allow? (type 'n' for none)"))
                
                if port.isnumeric():
                    os.system("sudo ufw allow " + port)
                    log("Allowed port: " + port)
                elif port == "n":
                    # ask for deny
                    port = input(question("What ports would you like to deny? (type 'n' for none)"))
                    if port.isnumeric():
                        os.system("sudo ufw deny " + port)
                        log("Blocked port: " + port)
                    elif port == "n":
                        notdone = False
                        break
                    else:
                        err("No port config because you cant do something simple!")
                        notdone = False
                        break
                else:
                    err("No port config because you cant do something simple!")
                    notdone = False
                    break
            elif portsq.lower() == 'n':
                notdone = False
                break
            else:
                err("No port conifg because you cant do something simple!")
                notdone = False
                break
    else:
        log("UFW is not installed, installing it...") 
        os.system("sudo apt install ufw") 
        log("UFW should be installed?")
        
        if fcfg + 1 == 1:
            warn("Cant find UFW directory!")
            return

        firewall_config()
        
    sshq = input(question("Would you like to allow port 22 (Check readme!) (y,n)"))
    if sshq == 'y':
        os.system("sudo ufw allow 22 && sudo ufw allow ssh")
        log("Opened SSH port")
    elif sshq != 'n':
        err("Its a simple y or n question, dont answer anything else buster.")
        firewall_config()

# This should write
def lightdm_config():
    # Edit file /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
    # add the following:
    # allow-guest = false
    # greeter-hide-users=true
    # greeter-show-manual-login=true
    # autologin-user=none <-- this broke our last comp image
    ldmq = input(question("Would you like to configure lightdm? (y,n)"))
    
    if ldmq == 'n':
        return
    elif ldmq != 'y':
        err("You cant even listen to basic commands?")
        lightdm_config()
        return

    path = "/usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf"
    if exists(path):
        settings = "\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true\nautologin-user=none"
        log("Adding settings:", settings, "to", path)
        
        lightdmconf = open(path, "a")
        lightdmconf.write(settings)
        lightdmconf.close()
    else:
        warn("Could not find lightdm config! Exiting lightdm config!.")
        return # don't know why I should have this here

def updates():
    updateq = input(question("Would you like to update/upgrade? (y,n)"))
    if updateq == 'y':
        os.system("sudo apt update")
        log("Finished sudo apt update")
        
        os.system("sudo apt upgrade")
        log("Ran sudo apt upgrade")

        os.system("sudo apt dist-upgrade")
        log("Ran sudo apt dist upgrade")
        
    elif updateq != 'n':
        err("Can you please type something that is accepted?")
        updates()

def remove_bad_apps():
    # Read from bad.txt line by line and plug in the program to sudo apt remove *prog*
    rmbaq = input(question("Would you like to remove bad apps? (y,n)"))
    
    if rmbaq == 'n':
        return
    elif rmbaq != 'y':
        err("Lets try this again..")
        remove_bad_apps()
        return
    
    badfile = open('bad.txt', 'r')  
    progs = badfile.readlines()
    
    for prog in progs:
        os.system("sudo apt remove " + prog)
    
    log("Finished removing bad applications, though please make sure to check for some more, as not all are listed here.")

def password_securing():
    # chmod 640 /etc/shadow
    # passord rules in /etc/login.defs
        # These password rules are:
        #     PASS_MAX_DAYS  90
        #     PASS_MIN_DAYS  10
        #     PASS_WARN_AGE  7
        
    psq = input(question("Would you like to secure/configure password policies? (y,n)"))
    if psq == 'n':
        return
    elif psq != 'y':
        err("Just put in the right input!")
        password_securing()
        return
    
    os.system("sudo chmod 640 /etc/shadow")
    log("Gave 640 permissions to /etc/shadow (where passwords are stored)")
    
    os.system("sudo apt install libpam-cracklib")    
    log("Installed libpam-cracklib")

    # Does password policies - not sure if I should be doing this this way
    with open('./preset_files/login.defs', 'r') as preset, open('/etc/login.defs', 'w') as logindefs:
        for line in preset:
            logindefs.write(line)
    log("Wrote preset ./preset_files/login.defs to /etc/login.defs!")
    
    with open('./preset_files/common-auth', 'r') as preset, open('/etc/pam.d/common-auth', 'w') as common_auth:
        for line in preset:
            common_auth.write(line)
    log("Wrote preset ./preset_files/common-auth to /etc/pam.d/common-auth")
    
    with open('./preset_files/common-password', 'r') as preset, open('/etc/pam.d/common-password', 'w') as common_password:
        for line in preset:
            common_password.write(line)
    log("Wrote preset ./preset_files/common-password to /etc/pam.d/common-password")
         
updates()
firewall_config()    
lightdm_config()
remove_bad_apps()
password_securing()