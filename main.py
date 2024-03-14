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
    return bordercolors.OKGREEN + q + bordercolors.ENDC
    
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
print(" - 3rd of all, FINISH FORENSIC QUESTIONS FIRST, BECAUSE YOU MAY REMOVE SOME IMPORTANT FILES, USERS, GROUPS, ETC.")
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

def preset_to_conf(preset, conf):
    # Writes backup
    with open(conf, 'r') as configfile, open('./backups/' + preset, 'w') as bak:
        for line in configfile:
            bak.write(line)
        configfile.close()
        bak.close()
    
    # Writes the config
    with open('./preset_files/' + preset, 'r') as presetfile, open(conf, 'w') as configfile:
        for line in presetfile:
            configfile.write(line)
        presetfile.close()
        configfile.close() 
            
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
    is_ssh, is_mail = False
    log("These are some setup questions: ")

    setupqssh = input(question(" - Is this an SSH server? Should this machine have SSH enabled? (y,n)"))
    if setupqssh == 'y':
        is_ssh = True
    elif setupqssh == 'n':
        is_ssh = False # This is just here to make sure..
    else:
        err("Lets try this again..")
        setup_questions()
        return is_ssh, is_mail

    setupqmail = input(question(" - Is this a mail server? (y,n)"))
    if setupqmail == 'y':
        is_mail = True
    elif setupqmail == 'n':
        is_mail = False
    else:
        err("Lets try this again.")
        setup_questions()
        return is_ssh, is_mail
        
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
        os.system("sudo apt install ufw -y") 
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
        os.system("sudo apt update -y")
        log("Finished sudo apt update")
        
        os.system("sudo apt upgrade -y")
        log("Ran sudo apt upgrade")

        os.system("sudo apt dist-upgrade -y")
        log("Ran sudo apt dist upgrade")
        
        os.system("update-manager -d")
        log("Ran forced UI update")
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
        os.system("sudo apt remove " + prog + " -y")
    
    log("Finished removing bad applications, though please make sure to check for some more, as not all are listed here.")
    
    log("END OF REMOVE BAD APPS")

def common_config():
    # with open('./preset_files/common-auth', 'r') as preset, open('/etc/pam.d/common-auth', 'w') as common_auth:
    #     for line in preset:
    #         common_auth.write(line)
    #     preset.close()
    #     common_auth.close()
    preset_to_conf('common-auth', '/etc/pam.d/common-auth')
    log("Wrote preset ./preset_files/common-auth to /etc/pam.d/common-auth")
    
    # with open('./preset_files/common-password', 'r') as preset, open('/etc/pam.d/common-password', 'w') as common_password:
    #     for line in preset:
    #         common_password.write(line)
    #     preset.close()
    #     common_password.close()
    preset_to_conf('common-password', '/etc/pam.d/common-password')
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
    
    os.system("chmod 640 /etc/passwd")
    log("Gave 640 permissions to /etc/shadow (user(s) info)")
    
    os.system("chmod 640 /etc/group")
    log("Gave 640 permissions to /etc/group (group(s) info)")

    os.system("sudo apt install libpam-cracklib -y")    
    log("Installed libpam-cracklib")
    
    os.system("sudo passwd -l root")
    log("Locked root account")


    # Does password policies - not sure if I should be doing this this way
    # with open('./preset_files/login.defs', 'r') as preset, open('/etc/login.defs', 'w') as logindefs:
    #     for line in preset:
    #         logindefs.write(line)
    #     preset.close()
    #     logindefs.close()
    preset_to_conf('login.defs', '/etc/login.defs')
    log("Wrote preset ./preset_files/login.defs to /etc/login.defs!")
    
    commonq = input(question("Would you like to configure common-auth and common-password? (y,n)"))
    
    if commonq == 'n':
        return
    elif commonq != 'y':
        err("Please input a valid option!")
    
    common_config()
    
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

    os.system("sudo apt install openssh-server ssh -y")
    log("Installing openssh-server and ssh packages")

    os.system("sudo ufw allow 22 && sudo ufw allow ssh")
    log("Opened SSH port")
    
    # with open("./preset_files/sshd_config", 'r') as preset, open("/etc/ssh/sshd_config", 'w') as sshdconfig:
    #     for line in preset:
    #         sshdconfig.write(line)
    #     preset.close()
    #     sshdconfig.close()
    
    preset_to_conf('sshd_config', '/etc/ssh/sshd_config')    

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

    os.system("sudo apt remove openssh-server ssh -y")
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

    # with open('./preset_files/sysctl.conf', 'r') as preset, open('/etc/sysctl.conf', 'w') as sysctl:
    #     for line in preset:
    #         sysctl.write(line)
    #     preset.close()
    #     sysctl.close()

    preset_to_conf('sysctl.conf', '/etc/sysctl.conf')

    os.system("sudo sysctl -p")
    log("Fixed up sysctl conf")
        
# From stack overflow - thanks, ivanleoncz
def read_and_parse(filename):
    data = []
    with open(filename, "r") as f:
        for line in f.readlines():
            data.append(line.split(":")[0])
        data.sort()
        # for item in data:
        #     print("- " + item)

    return data

# This will is a questionare, which will ask for the list of users, excluding the admins,
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
        
         
    for person in read_and_parse("/etc/passwd"):
        userid = pwd.getpwnam(person).pw_uid
        if userid >= 1000 and person not in users:
            # User exists when they are not supposed to. Remove them.
            os.system("sudo userdel -rf " + person)
            warn("Removed user: " + person) 
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
    os.system("sudo apt install members -y")
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
        log("Ok.")
        return
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
    
    os.system("sudo apt install auditd -y && auditctl -e 1")
    log("Enabled audit")
    
    os.system("service auditd start")
    log("Started auditd service")

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

    os.system("sudo apt remove samba samba-common samba-common-bin -y && sudo apt purge samba -y")
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
    
    # with open('./preset_files/20auto-upgrades', 'r') as preset, open('/etc/apt/apt.conf.d/20auto-upgrades', 'w') as autoupgrades:
    #     for line in preset:
    #         autoupgrades.write(line)
    #     preset.close()
    #     autoupgrades.close()
    
    preset_to_conf('20auto-upgrades', '/etc/apt/apt.conf.d/20auto-upgrades')
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
    
    os.system("sudo apt install apparmor -y")
    os.system("apt install apparmor-utils -y")

    log("Apparmor should be installed?")

    os.system("aa-enforce /etc/aparmor.d/usr.bin.*")
    os.system("awk '/GRUB_CMDLINE_LINUX/ {print;print \"GRUB_CMDLINE_LINUX=\"apparmor=1 security=apparmor\"\";next}1' /etc/default/grub > app_armor_conf")
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

def mail_config():
    q = input(question("Would you like to setup and configure \"this mail server\" (y,n)"))
    if q == 'n':
        log("Ok")
        return
    elif q != 'y':
        err("Please input something accepted?!?")
        mail_config()
        return        

    log("Installing Postfix")
    os.system("apt install postfix -y")
    log("Installed Postfix")

    os.system("ufw allow 25")
    log("Alloweds port 25")

def disconfig_mail():
    q = input(question("Would you like to remove the mail server aspects (y,n)"))
    if q == 'n':
        log("Ok")
        return
    elif q != 'y':
        err("Please input something accepted?!?")
        mail_config()
        return        

    log("Removing Postfix")
    os.system("apt remove postfix -y && apt purge postfix -y")
    log("Removed Postfix")

    os.system("ufw deny 25")
    log("Blocked port 25")

def disable_nginx():
    q = input(question("Would you like to disable nginx? (saying no means enable it) (y,n)"))
    if q == 'n':
        # Enable nginx
        os.system("systemctl start nginx")
    elif q == 'y':
        # Disable nginx
        os.system("systemctl disable nginx")
    else:
        err("Please input y or n")
        disable_nginx()
        return

def ftp_config():
    q = input(question("Would you like to configure FTP? (y,n)"))
    if q == 'n':
        log("ok")
        return
    elif q != 'y':
        err("Do smth right")
        ftp_config()
        return
    
    log("Installing ftp packages")
    os.system("apt install vsftpd ftp -y")
    log("Installed ftp packages")

    # with open("./preset_files/vsftpd.conf", 'r') as preset, open("/etc/vsftpd.conf", 'w') as vsftpdconf:
    #     for line in preset:
    #         vsftpdconf.write(line)
    #     preset.close()
    #     vsftpdconf.close()

    preset_to_conf('vsftpd.conf', '/etc/vsftpd.conf')
    log("Wrote preset: vsftpd.conf to /etc/vsftpd.conf") 

    q = input(question("Would you like to enable vsftpd service? Check Readme (y,n)"))
    if q == 'y':
        os.system("systemctl enable vsftpd")
        os.system("systemctl start vsftpd")
        log("Started vsftpd services")
    else:
        os.system("systemctl stop vsftpd")
        log("Stoped vsftpd service")

# Work in progress!
def firefox_config():
    q = input(question("Would you like to config firefox?"))
    if q == 'n':
        return
    if q != 'n':
        err("Do smth right")
        firefox_config()
        return
    
    log("Configuring firefox")

    os.system("snap remove firefox")
    log("Making sure that firefox is not installed through snap")

    os.system("apt install firefox -y")
    log("Installed (or updated) firefox package")

    log("You do not have to do this, as you can just set the settings in the Firefox settings.")
    userjs_path = input(question("Please paste in the path for the firefox user.js file (n to skip): "))
    
    if userjs_path == 'n':
        return
    
    with open("./preset_files/user.js", 'r') as preset, open(userjs_path, 'w') as userjs:
        for line in preset:
            userjs.write(line)
        preset.close()
        user_exists.close() 
        log("Wrote preset user.js to " + userjs_path)

def selinux_config():
    q = input(question("Would you line to configure (and enable) SELinux (y,n)"))
    if q == 'n':
        return
    elif q != 'y':
        log("write y or n")
        selinux_config()
        return
    
    log("Installing packages for SELinux")
    os.system("apt install policycoreutils selinux-utils selinux-basics")
    
    log("Activating SELinux")
    os.system("selinux-activate")
    log("Activated SELinux")
    
    os.system("selinux-config-enforcing")
    os.system("Set SELinux mode to enforcing")
    
    warn("------------------")
    err("-------------------")
    
    log("PLEASE REBOOT THIS WHEN YOU CAN SO SELINUX ENFORCING MODE WILL GET APPLIED!")
    
    warn("------------------")
    err("-------------------")

def what_to_do_next():
    log("There are some things that this script can't do very well. So here are a list of things to do since we are done.")
    
    log(" - Check /etc/hosts to make sure that there are no malicous \"redirects\"")
    log(" - Check /etc/passwd for users whose uid is 0 (only root is supposed to have uid of zero)")
    log(" - Please run the virus scanners: clamav, rkhunter and chkrootkit")
    log(" - Please check services to see if they shouldn't be used (try to use bum)")
    log("     - For example, if this is *not* a mail server, uninstall and remove the postfix server")
    log(" - Check /etc/sudoers.d and /etc/sudoers for suspicous configs")

is_ssh, is_mail = setup_questions()           
updates()
firewall_config()     

if is_ssh:
    config_ssh()
else:
    disconfig_ssh()

if is_mail:
    mail_config()
else:
    disconfig_mail()

ask_ufw_stat() 
disable_nginx()
lightdm_config()
remove_bad_apps()
password_securing()
networking_config()
users()
audit_config()
scan_media_files()
periodic_updates()
apparmor_config()
ftp_config()
# firefox_config()
selinux_config()

log("Setting home directory perms")
os.system("for i in $(mawk -F: '$3 > 999 && $3 < 65534 {print $1}' /etc/passwd); do [ -d /home/${i} ] && chmod -R 750 /home/${i}; done")

what_to_do_next()

print(bordercolors.OKBLUE + "You are all done, happy patroling!" + bordercolors.ENDC)
