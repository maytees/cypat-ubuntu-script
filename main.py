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

def ask_ufw_stat():
    q = input(question("Would you like to see UFW status? (Just to make sure nothing is wrong) (y,n)"))
    if q == 'n':
        warn("Ok.")
        return
    elif q != 'y':
        err("Let's just default to no..")
        return

    # Debugging purposes
    log("UFW Status: ")
    os.system("sudo ufw status")

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
    
    os.system("sudo passwd -l root")
    log("Locked root account")


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
    q = input(question("Would you like to do reccomended modifications for SSH? (not-dis) (y,n)"))
    if q == 'n':
        return
    elif q != 'y':
        err("Let's try this again.")
        config_ssh()
        return

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

    os.system("sudo service sshd reload")
    log("Reloaded sshd service")

    log("END OF CONFIG SSH")

# Removes ssh packages and closes ports
def disconfig_ssh():
    q = input(question("Would you like to do reccomended modifications for SSH? (dis) (y,n)"))
    if q == 'n':
        return
    elif q != 'y':
        err("Let's try this again.")
        disconfig_ssh()
        return

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

def autouser_config():
    
    log("Starting automatic labor")

    admins_file = open("./settings/admins.txt", 'r')
    non_admins_file = open("./settings/non-admins.txt", 'r')

    adminsdat = admins_file.read()
    nonadminsdat = non_admins_file.read()

    adminswpass = adminsdat.splitlines()
    non_admins = nonadminsdat.splitlines()

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

    print(bordercolors.HEADER)

    # Loop through the users and check if they exists
    for user in users:
        if user_exists(user):
            # Check some other stuff, like,
            #  if they are supposed to be admin or not, etc 
            if user in admins:
                if user in sys_admins:
                    print(user, "is ok!")
                    # log(user + " is okay! Passing.")
                    pass
                else:
                    os.system("sudo usermod -a -G sudo " + user)
                    print("Added " + user + " to sudo group (admins)")
            else:
                if user in sys_admins:
                    os.system("sudo gpasswd -d " + user + " sudo")
                    print("Removed " + user + " from sudo group (admins), b/c they are not supposed to be there!")
                else:
                    print(user, "is ok!")
                    # log(user + " is okay! Passing.")
                    pass
        else:
            # Create the new user
            #   - check if they are supposed to be an admin
            os.system("sudo useradd -m " + user)
            print("Created user -  " + user + " beacuse they are supposed to be a user, though they weren't :(")

            if user in admins:
                # Add user to sudo group
                os.system("sudo usermod -a -G sudo " + user)
                log("Added new user (" + user + ") to sudo (admins) group, b/c they are supposed to be there")
                log("Please go change this person's password to - " + admins[user])

    print(bordercolors.ENDC)
    
def manualuser_config():
    # Ask inputer if they want to add/remove user, the same way as the port thing
    rem = input(question("Would you like to remove any users? (y,n)"))
    if rem == 'y':
        notdone = True
        while notdone:
            user = input(question("What user would you like to remove? (n for none)"))
            if user == 'n':
                warn("Ok, exiting")
                break

            os.system("sudo userdel -r " + user)
            log("removed user: " + user)
    elif rem == 'n':
        create = input(question("Would you like to add any users? (y,n)"))
        if create == 'y':
            notdone = True
            while notdone:
                user = input(question("What user would you like to create? (n for none)"))
                if user == 'n':
                    warn("Ok, exiting")
                    break

                os.system("sudo useradd -m " + user)
                log("Created new user: " + user)
        elif create == 'n':
            err("Nothing. Okay.")
            return
        else:
            err("Lets try this agian.")
    else:
        err("Lets try this again.")
        manualuser_config()
        return

def users():
    uq = input(question("Would you like to configure the users? (y,n)"))
    if uq == 'n':
        return
    elif uq != 'y':
        err("Lets try this again, since you cannot input y or n")
        users()
        return

    log("Installing packages - members")
    os.system("sudo apt install members")
    log("Installed package - members")

    autolabor = input(question("Would you like this script to do some automatic user handling? (y,n)"))
    if autolabor == 'n':
        log("Ok, more work for you..")
    elif autolabor == 'y':
        autouser_config()
    else:
        warn("Really gonna make yourself redo this whole users thing...")
        return

    manuallabor = input(question("Would you like to add/remove any more users by yourself? (y,n)"))
    if manuallabor == 'n':
        log("Ok, less work for you..")
    elif manuallabor == 'y':
        manualuser_config()
    else:
        warn("Really gotta do this whole users thing again..")
        return

def audit_config():
    q = input(question("Would you like me (the script) to config auditing? (y,n)"))
    if q == 'n':
        err("Bye.")
        return
    elif q != 'y':
        err("Ok lets try this again.")
        audit_config()
        return

    log("Configuring audit(s?).")

    os.system("sudo apt install auditd && auditctl -e 1")
    log("Enabled audit")

def rem_samba():
    q = input(question("Would you like to remove SAMBA stuff? (comm with Windows) (y,n)"))
    if q == 'n':
        err("Ok, bye.")
        return
    elif q != 'y':
        err("Why dont you try listening?")
        rem_samba()
        return

    log("Removing samba")

    os.system("sudo apt remove samba samba-common samba-common-bin && sudo apt purge samba")
    log("Removed samba packages and directories")

    os.system("sudo rm -rf /var/lib/samba/printers/x64")
    os.system("sudo rm -rf /var/lib/samba/printers/W32X86")
    log("Removed samba directories")

def periodic_updates():
    q = input(question("Would you like to enable reccomended periodic updates? (y,n)"))
    if q == 'n':
        err("Ok, bye.")
        return
    elif q != 'y':
        err("Please just do y or n")
    
    log("Setting periodic updates")
    
    with open('./preset_files/20auto-upgrades', 'r') as preset, open('/etc/apt/apt.conf.d/20auto-upgrades', 'w') as autoupgrades:
        for line in preset:
            autoupgrades.write(line)
        preset.close()
        autoupgrades.close()
        
        log("Wrote preset - preset_files/20auto-upgrades to /etc/apt/apt.conf.d/20auto-upgrades")

def apparmor_config():
    q = input(question("Would you like to configure apparmor? (y,n)"))
    if q == 'n':
        err("Ok bye.")
        return
    elif q != 'y':
        err("Do something right")
        apparmor_config()
        return
    
    os.system("sudo apt install apparmor")
    os.system("apt install apparmor-utils")

    log("Apparmor should be installed?")

    os.system("aa-enforce /etc/aparmor.d/usr.bin.*")
    os.system("awk '/GRUB_CMDLINE_LINUX/ {print;print "GRUB_CMDLINE_LINUX="apparmor=1 security=apparmor"";next}1' /etc/default/grub > app_armor_conf")
    os.system("cp app_armor_conf /etc/default/grub")
    os.system("rm app_armor_conf")

    os.system("update-grub")

    os.system("aa-enforce /etc/apparmor.d/usr.bin.*")

    log("Enforced apparmor grub config")
    
def scan_media_files():
    q = input(question("Would you like to remove media files? (y,n)"))
    if q == 'n':
        err("Ok, bye.")
        return
    elif q != 'y':
        err("Listen!N!NN!N!N")
        scan_media_files()
        return

    log("Removing media files.")

    log("Please remove the following mp3 files -")
    mp3files = subprocess.getoutput("sudo find / -xdev -type f -name \"*.mp3\"")

    log("Please remove the following mp4 files -")
    mp4files = subprocess.getoutput("sudo find / -xdev -type f -name \"*.mp4\"")

def what_to_do_next():
    log("There are some things that this script can't do very well. So here are a list of things to do since we are done.")
    
    log(" - Check /etc/hosts to make sure that there are no malicous \"redirects\"")
    log(" - Check /etc/passwd for users whose uid is 0 (only root is supposed to have uid of zero)")

setup_questions()             
updates()
firewall_config()     

if is_ssh:
    config_ssh()
else:
    disconfig_ssh()

ask_ufw_stat()

lightdm_config()
remove_bad_apps()
password_securing()
networking_config()
users()
audit_config()
scan_media_files()
periodic_updates()

log("Setting home directory perms")
os.system("for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do [ -d /home/${i} ] && chmod -R 750 /home/${i}; done")

what_to_do_next()

print(bordercolors.OKBLUE + "You are all done, happy patroling!" + bordercolors.ENDC)
