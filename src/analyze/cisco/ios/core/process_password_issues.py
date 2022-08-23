from ciscoconfparse import CiscoConfParse

from ....common.passwords.password_utils import decrypt_cisco_password_7, check_password

def get_exposed_passwords(filename):
    password_status = []

    parser = CiscoConfParse(filename, syntax='ios')
    password0_list= parser.find_objects(r'username .+ password 0 .+')
    password7_list= parser.find_objects(r'username .+ password 7 .+')

    for pas in password0_list:
        status = "Secure password" if check_password(pas.text.split(' password 0 ',1)[1]) else "Insecure password"
        key = pas.text.split(' password 0 ',1)[1]
        username = pas.text.split(" ")[1]
        password_status.append({"password": key, "status": status, "username": username, "password_type": 0})

    for pas in password7_list:
        clear_pas = decrypt_cisco_password_7(pas.text.split(' password 7 ',1)[1])
        status = "Secure password" if check_password(clear_pas) else "Insecure password"
        username = pas.text.split(" ")[1]
        password_status.append({"password": clear_pas, "status": status, "username": username, "password_type": 7, "encrypted_password": pas.text.split(' password 7 ',1)[1]})
    
    return password_status

