import os
import sys
import time
import pwd
import subprocess
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
    print(bordercolors.FAIL + msg + bordercolors.ENDC + '\n')

def warn(msg):
    print(bordercolors.WARNING + msg + bordercolors.ENDC + '\n')

def log(msg):
    print(bordercolors.OKCYAN + msg + bordercolors.ENDC + '\n')

def question(q):
    return bordercolors.OKGREEN + q + bordercolors.ENDC + '\n'
    
# Checks if script was run with root permissions -
# Not inspired by stack overflow, not at all
#    Thanks, Dmytro
isroot = os.geteuid() == 0

if not isroot:
    sys.exit(bordercolors.FAIL + "Please run the script as root!" + bordercolors.ENDC)

warn("Please make sure that you read the readme before running this!")

print(bordercolors.OKBLUE + "\nWelcome to this very cool script, which will help you.." + bordercolors.ENDC)
print(bordercolors.HEADER + "There are a few things you must do before running this." + bordercolors.ENDC)

print(bordercolors.OKCYAN)
print(" - 1st of all, I would like you to paste in the non admin users in the ./settings/non-admins.txt file in the source root")
print("    - Refer to the ./examples/non-admins-example.txt for a reference on formatting")
print(" - 2nd of all, I would like you to paste in the administrator users in the ./settings/admins.txt, please separate the passwords with a space")
print("    - Refer to the ./examples/admins-example.txt for a reference on formatting")
print(bordercolors.ENDC) #ends cyan color 

err("Please go make changes before you continue.")

ready = input(question("Are you ready to move on? (y,n) "))
if ready == 'n':
    sys.exit(bordercolors.FAIL + "Bye." + bordercolors.ENDC)
elif ready != 'y':
    sys.exit(bordercolors.FAIL + "Exiting beacuse you canot input y or n.")

log("Ok, we are ready to move on :)\n")

print(bordercolors.WARNING + "--------------------------------------" + bordercolors.ENDC)
print("\n")

is_ssh = False
is_mail = False

def user_exists(username):
    try:
        pwd.getpwnam(username) 
    except KeyError:
        return False
    
    return True 

# Helper
def is_admin(user, admins):
    if user in admins:
        return True
    return False
    
def setup_questions():
    log("These are some setup questions: ")
    
    global is_ssh
    global is_mail

    setupqssh = input(question(" - Is this an SSH server? Should this machine have SSH enabled? (y,n)"))
    if setupqssh == 'y':
        is_ssh = True
    elif setupqssh == 'n':
        is_ssh = False # This is just here to make sure..
    else:
        err("Lets try this again..")
        setup_questions()
        return

    setupqmail = input(question(" - Is this a mail server? (y,n)"))
    if setupqmail == 'y':
        is_mail = True
    elif setupqmail == 'n':
        is_mail = False
    else:
        err("Lets try this again.")
        setup_questions()
        return
        
    log("END OF SETUP QUESTIONS")    

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
        
    # sshq = input(question("Would you like to allow port 22 (Check readme!) (y,n)"))
    # if sshq == 'y':
    #     os.system("sudo ufw allow 22 && sudo ufw allow ssh")
    #     log("Opened SSH port")
    # elif sshq != 'n':
    #     err("Its a simple y or n question, dont answer anything else buster.")
    #     firewall_config()
    
    # if IS_SSH:
    #     os.system("sudo ufw allow 22 && sudo ufw allow ssh")
    #     log("Open SSH port")
    # else:
    #     os.system("sudo ufw deny 22 && sudo ufw deny ssh")
    #     log("Closed SSH port")

    log("END OF FIREWALL CONFIG")

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
        log(f"Adding settings: {settings}, to {path}")
        
        lightdmconf = open(path, "a")
        lightdmconf.write(settings)
        lightdmconf.close()
    else:
        warn("Could not find lightdm config! Exiting lightdm config!.")
        return # don't know why I should have this here
    
    log("END OF LIGHTDM CONFIG")

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
    
    log("END OF UPDATES")

def remove_bad_apps():
    # Read from bad.txt line by line and plug in the program to sudo apt remove *prog*
    rmbaq = input(question("Would you like to remove bad apps? (y,n)"))
    
    if rmbaq == 'n':
        return
    elif rmbaq != 'y':
        err("Lets try this again..")
        remove_bad_apps()
        return
    
    badfile = open('./settings/bad.txt', 'r')  
    progs = badfile.readlines()
    
    for prog in progs:
        os.system("sudo apt remove " + prog)
    
    log("Finished removing bad applications, though please make sure to check for some more, as not all are listed here.")
    
    log("END OF REMOVE BAD APPS")

def common_config():
    with open('./preset_files/common-auth', 'r') as preset, open('/etc/pam.d/common-auth', 'w') as common_auth:
        for line in preset:
            common_auth.write(line)
        preset.close()
        common_auth.close()        
    log("Wrote preset ./preset_files/common-auth to /etc/pam.d/common-auth")
    
    with open('./preset_files/common-password', 'r') as preset, open('/etc/pam.d/common-password', 'w') as common_password:
        for line in preset:
            common_password.write(line)
        preset.close()
        common_password.close()
    log("Wrote preset ./preset_files/common-password to /etc/pam.d/common-password")
    
    log("END OF COMMON CONFIG")    

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
        preset.close()
        logindefs.close()
    log("Wrote preset ./preset_files/login.defs to /etc/login.defs!")
    
    commonq = input(question("Would you like to configure common-auth and common-password? (y,n) (this is not reccomended)"))
    
    if commonq == 'n':
        return
    elif commonq != 'y':
        err("Please input a valid option!")
    
    common_config()
    
    warn("Please open a new terminal tab and check if `sudo echo hi` has worked, if not, then run: sudo apt remove libpam-cracklib")
    
    log("END OF PASSWORD SECURING")

# Allows ssh ports, install openssh-server and ssh packages,
#   configures /etc/ssh/sshd_config
def config_ssh():
    os.system("sudo apt install openssh-server ssh")
    log("Installing openssh-server and ssh packages")

    os.system("sudo ufw allow 22 && sudo ufw allow ssh")
    log("Opened SSH port")
    
    # Config /etc/ssh/sshd_config
    # NOTE TO SELF - MAKE SURE TO CLOSE THE FILE AFTER
    with open("./preset_files/sshd_config", 'r') as preset, open("/etc/ssh/sshd_config", 'w') as sshdconfig:
        for line in preset:
            sshdconfig.write(line)
        preset.close()
        sshdconfig.close()
        
    log("END OF CONFIG SSH")

# Removes ssh packages and closes ports
def disconfig_ssh():
    os.system("sudo apt remove openssh-server ssh")
    log("Removed SSH packages")

    os.system("sudo ufw deny 22 && sudo ufw deny ssh")
    log("Closed SSH port")
    
    log("END OF DISCONFIG SSH")

# Will most likely move firewall_config() into here, but for now I will sleep : )
def networking_config():
    ncq = input(question("Would you like to config networking stuff? (y,n) (you should :)"))
    if ncq == 'n':
        return
    elif ncq != 'y':
        err("Lets try this again you doofus")
        networking_config()
        return

    with open('./preset_files/sysctl.conf', 'r') as preset, open('/etc/sysctl.conf', 'w') as sysctl:
        for line in preset:
            sysctl.write(line)
        preset.close()
        sysctl.close()
        os.system("sudo sysctl -p")
        log("Fixed up sysctl conf")

# This will be a questionare, which will ask for the list of users, excluding the admins,
#  and will organize everything/everyone

def users():
    uq = input(question("Would you like to configure the users? Keep in mind that this may not be stable (y,n)"))
    if uq == 'n':
        return
    elif uq != 'y':
        err("Lets try this again, since you cannot input y or n")
        users()
        return
    
    log("Installing packages - members")
    os.system("sudo apt install members")    
    log("Installed package - members")

    admins_file = open("./settings/admins.txt", 'r')
    non_admins_file = open("./settings/non-admins.txt", 'r')
    
    adminsdat = admins_file.read()
    nonadminsdat = non_admins_file.read()
    
    adminswpass = adminsdat.splitlines()
    non_admins = nonadminsdat.splitlines()

    # Debugging purposes
    # print(adminswpass)
    # print(non_admins)
     
    admins_file.close()
    non_admins_file.close()
    
    # Split the admins into a dictionary, with a "name : pasword" format 
    admins = {}    
    users = []
    for admin in adminswpass:
        split = admin.split()
        admins[split[0]] = split[1]   
    
    # Add users to users list
    for non_admin in non_admins:
        users.append(non_admin)
    
    for adminusername in admins.keys():
        users.append(adminusername)
    
    sys_admins = subprocess.getoutput("members sudo")    
    log("The currect admins on this image are: " +  sys_admins)

    # Loop through the users and check if they exists
    for user in users:
        if user_exists(user):
            # Check some other stuff, like,
            #  if they are supposed to be admin or not, etc 
            if user in admins:
                if user in sys_admins:
                    print(user, "is ok")
                else:
                    print(user, "is not ok, because they are supposed to be an admin")
            else:
                if user in sys_admins:
                    print(user, "is not ok, because they are not supposed to be an admin")
                else:
                    print(user, "is ok")
        else:
            # Remove the user, because they are not suppsoed
            #  to be there
            pass
                                     
def what_to_do_next():
    log("There are some things that this script can't do very well. So here are a list of things to do since we are done.")
    
    log(" - Check /etc/hosts to make sure that there are no malicous \"redirects\"")

setup_questions()             
updates()
firewall_config()     

print(is_ssh)

if is_ssh:
    config_ssh()
else:
    disconfig_ssh()
# Debugging purposes
log("UFW Status: ")    
os.system("sudo ufw status")

lightdm_config()
remove_bad_apps()
password_securing()
networking_config()
users()

what_to_do_next()

print(bordercolors.OKBLUE + "You are all done, happy patroling!" + bordercolors.ENDC)
