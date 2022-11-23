# Cyberpatriot UBUNTU Script

### TERMS OF USE -

This script/project cannot be used for Cyberpatriot teams other than Cybarra.

This can be used for learning or makingy your own script.

### Status (more to come as this script progresses) -

- [x] Updates
    - [x] Dist
    - [x] Normal
    - [x] Config security update rules
- [x] SSH config
    - [x] Allow/Deny port 22
    - [x] sshd_config file config
- [ ] Mail server config
    - [ ] Postfix
    - [ ] Allow port(s) (25)
- [x] UFW Config/setup
- [x] Lightdm config
- [x] User remove/add
    - [Stack Overflow]("https://stackoverflow.com/questions/2540460/how-to-check-if-a-user-exists-in-a-gnu-linux-os-using-python")
- [ ] Group remove/add
    - [x] Add users who are supposed to have admin to sudo group
    - [Stack Overflow]("https://stackoverflow.com/questions/2540460/how-to-check-if-a-user-exists-in-a-gnu-linux-os-using-python")
- [x] Passwords
    - [x] Password rules - in /etc/login.defs
    - [x] chmod 640 /etc/shadow
- [x] Remove bad applications
- [x] Remove media files (mp3, mp4, jpeg, etc) 
- [ ] Anti virus scanner (clamav, rkhunter, chrootkit)
- [ ] Firefox Config (not sure how this will be done, there most likely is a config file)
- [ ] Grub config
- [x] Remove Samba access (connection between Win and Linux, Google for more info)
  - `sudo apt-get remove --purge samba`
- [x] SYSCTL Config (/etc/sysctl.conf)
- [x] Audit config
- [x] Apparmor