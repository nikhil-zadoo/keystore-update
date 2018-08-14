#!/bin/python
#Author - nikhil.zadoo@gmail.com

from dateutil.parser import parse
import argparse
import getpass
import readline
import sys
import os.path
import subprocess
import re
import OpenSSL.crypto
import datetime


class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def take_input(msg):
    value = raw_input(bcolors.BOLD + msg + bcolors.ENDC)
    return value


def update_keystore_sep():
    if args.sep_cert_file is None:
        msg = "Please Enter the certificate file location : "
        sep_cert_file = take_input(msg)
    else:
        sep_cert_file = args.sep_cert_file

    if not os.path.exists(sep_cert_file):
        print(bcolors.FAIL + "The path entered for cert file '%s' does not exist!!!" % sep_cert_file + bcolors.ENDC)
        sys.exit(2)

    try:
        cert_modulus = subprocess.check_output(['openssl', 'x509', '-in', sep_cert_file, '-noout', '-modulus'], stderr=subprocess.STDOUT)
    except Exception:
        print(bcolors.FAIL + "The certificate file seems to be corrupted. Please check the cert file again!" + bcolors.ENDC)
        print(bcolors.FAIL + "You can use the below command!" + bcolors.ENDC)
        print(bcolors.FAIL + "openssl x509 -in <Cert_file> -noout -text" + bcolors.ENDC)
        sys.exit(2)

    if args.sep_key_file is None:
        msg = "Please Enter the Key File file location : "
        sep_key_file = take_input(msg)
    else:
        sep_key_file = args.sep_key_file

    if not os.path.exists(sep_key_file):
        print(bcolors.FAIL + "The path entered for key  file '%s' does not exist!!!" % sep_key_file + bcolors.ENDC)
        sys.exit(2)

    output = open(sep_key_file, "r").read()
    if len(re.findall(pattern="PRIVATE KEY-----", string=output)) != 2:
        print(bcolors.FAIL + "The key cert format seems to be corrupted. Please also make sure the correct path to the intended key file was given" + bcolors.ENDC)
        sys.exit(2)

    try:
        key_modulus = subprocess.check_output(['openssl', 'rsa', '-in', sep_key_file, '-noout', '-modulus', '-passin', 'pass:' + ""], stderr=subprocess.STDOUT)
    except Exception:
        if args.src_passwd is None:
            msg = "Please enter the password for the key file"
            src_passwd = getpass.getpass(bcolors.BOLD + msg + bcolors.ENDC + " : ")
        else:
            src_passwd = args.src_passwd

        try:
            key_modulus = subprocess.check_output(['openssl', 'rsa', '-in', sep_key_file, '-noout', '-modulus', '-passin', 'pass:' + src_passwd], stderr=subprocess.STDOUT)
        except Exception:
            print(bcolors.FAIL + "The password entered for key file is incorrect" + bcolors.ENDC)
            print(bcolors.FAIL + "Use the command below to manually check the password" + bcolors.ENDC)
            print(bcolors.BOLD + "openssl rsa -in <key_file> -noout -passin pass:<password> -text" + bcolors.ENDC)
            sys.exit(2)

    if cert_modulus == key_modulus:
        print(bcolors.BOLD + "Looks good. The modulus of cert and key are Matching." + bcolors.ENDC)
    else:
        print(bcolors.FAIL + "The modulus of the cert and key dont match. Please get in touch with the person who created the CSR" + bcolors.ENDC)
        print(bcolors.FAIL + "To check the modulus of the certificate file use the below command" + bcolors.ENDC)
        print(bcolors.FAIL + "openssl x509 -in <Cert_file> -noout -modulus" + bcolors.ENDC)
        print(bcolors.FAIL + "To check the modulus of the key file use the below command" + bcolors.ENDC)
        print(bcolors.FAIL + "openssl rsa -in <Cert_file> -noout -modulus" + bcolors.ENDC)
        sys.exit(2)

    if args.dest is None:
        msg = "Please enter destination keystore file location : "
        dest = take_input(msg)
    else:
        dest = args.dest
    if not os.path.exists(dest):
        print(bcolors.FAIL + "The path entered for destination does not exist!!!" + bcolors.ENDC)
        sys.exit(2)

    if args.dest_passwd is None:
        msg = "Please enter the password for the destination keystore"
        dest_passwd = getpass.getpass(bcolors.BOLD + msg + bcolors.ENDC + " : ")
    else:
        dest_passwd = args.dest_passwd

    print(bcolors.BOLD + "Extracting the key and changing the password to match that of the destination keystore" + bcolors.ENDC)
    open("temp_decr.key", "w").close()
    try:
        subprocess.check_output(['openssl', 'rsa', '-in', sep_key_file, '-out', 'temp_decr.key' , '-passin', 'pass:' + src_passwd], stderr=subprocess.STDOUT)
        subprocess.check_output(
        ['openssl', 'rsa', '-aes256', '-in',  'temp_decr.key', '-out', 'temp.key', '-passout', 'pass:' + dest_passwd],
        stderr=subprocess.STDOUT)
    except Exception:
        print(bcolors.FAIL + "There was issue while creating the temporary files. please check if you have write permissions in the dir" + bcolors.ENDC)
        sys.exit(2)

    update_keystore_p12_update("",dest, dest_passwd, "temp.key", sep_cert_file )


def update_keystore_p12_update(source, dest, dest_passwd, temp_key="temp.key", temp_crt="temp.crt"):
    operation_on_flag = "p12"
    if args.alias is None:
        msg = "Please enter the alias name to be updated: "
        alias = take_input(msg)
    else:
        alias = args.alias

    open("temp.p12", "w").close()
    print(bcolors.BOLD + "Creating new temporary p12 file as temp.p12 to be exported to the keystore" + bcolors.ENDC)
    subprocess.check_output(
        ['openssl', 'pkcs12', '-export', '-in', temp_crt, '-inkey', temp_key, '-name', alias,
         '-out', 'temp.p12', '-passin', 'pass:' + dest_passwd, '-passout', 'pass:' + dest_passwd
         ], stderr=subprocess.STDOUT)

    print(bcolors.BOLD + "Checking if the alias already exists!" + bcolors.ENDC)
    try:
        output = subprocess.check_output(
            ['keytool', '-list', '-v', '-alias', alias, '-keystore', dest, '-storepass', dest_passwd],
            stderr=subprocess.STDOUT)
    except Exception:
        print(bcolors.BOLD + "The alias entered does not exist. Adding a new Alias" + bcolors.ENDC)
        update_keystore_p12_add(alias, dest, dest_passwd)
    else:
        print(bcolors.BOLD + "Alias already exists. Replacing it now!" + bcolors.ENDC)
        update_keystore_cert_del_add(output, operation_on_flag ,alias, dest, dest_passwd, source)


def update_keystore_p12_add(alias, dest, dest_passwd):
    try:
        subprocess.check_output(['keytool', '-importkeystore', '-srckeystore', 'temp.p12', '-destkeystore', dest,
                                 '-srcstoretype', 'PKCS12', '-deststoretype', 'JKS', '-srcalias', alias, '-destalias',
                                 alias, '-deststorepass', dest_passwd, '-srcstorepass', dest_passwd], stderr=subprocess.STDOUT)
    except Exception:
        print(
        bcolors.FAIL + "There was issue adding the temp p12 file to keystore" + bcolors.ENDC)
        print(bcolors.FAIL + "Use the command below to manually check the password" + bcolors.ENDC)
        print(bcolors.BOLD + "keytool -importkeystore -srckeystore temp.p12 -destkeystore \
        <Dest_keystore_path> -srcstoretype PKCS12 -deststoretype JKS -srcalias <alias> \
        -destalias <alias> -deststorepass <dest_keystore_pass> -srcstorepass <dest_keystore_pass>" + bcolors.ENDC)
        sys.exit(2)
    print(bcolors.OKGREEN + "The alias %s has been added successfully to the dstination keystore" %alias + bcolors.ENDC)
    print(bcolors.OKGREEN + "Details of the Alias '%s' Added " % alias + bcolors.ENDC)
    output = subprocess.check_output(['keytool', '-list', '-v', '-alias', alias, '-keystore', dest, '-storepass', dest_passwd], stderr=subprocess.STDOUT)
    print(bcolors.OKBLUE + output + bcolors.ENDC)


def update_keystore_p12_prep(source):
    if args.src_passwd is None:
        msg = "Enter the source p12 file password"
        src_passwd = getpass.getpass(bcolors.BOLD + msg + bcolors.ENDC + " : ")
    else:
        src_passwd = args.src_passwd
    p12_file = open(source, mode='r').read()

    try:
        p12_decoded = OpenSSL.crypto.load_pkcs12(p12_file, src_passwd)
    except:
        print(bcolors.FAIL + "Check if the password of p12 file is correct" + bcolors.ENDC)
        print(bcolors.FAIL + "Use he command below" + bcolors.ENDC)
        print(bcolors.FAIL + "openssl pkcs12 -in <P12_file> -info" + bcolors.ENDC)
        sys.exit(2)

    print(bcolors.BOLD + "Extracting and decrypting the key into temporary file temp_decr.key" + bcolors.ENDC )
    open("temp_decr.key", "w").write(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, p12_decoded.get_privatekey()))
    print(bcolors.BOLD + "Extracting Cert file into temporary file tmep.crt" + bcolors.ENDC)
    open("temp.crt", 'w').write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, p12_decoded.get_certificate()))
    open("tempCA.crt", "w").close()

    try:
        for i in range(len(p12_decoded.get_ca_certificates()) - 1, -1, -1):
            if i == len(p12_decoded.get_ca_certificates()) - 1:
                open("tempCA.crt", "w").write(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, p12_decoded.get_ca_certificates()[i]))
            else:
                open("tempCA.crt", "a").write(
                    OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, p12_decoded.get_ca_certificates()[i]))
    except Exception as exp:
        print("NO CA file persent")
        print(exp)
    else:
        print(bcolors.BOLD + "Extracted the CA files to temp file tempCA.crt" + bcolors.ENDC)

    open("temp.crt", "a").write(open("tempCA.crt", "r").read())
    if args.dest is None:
        msg = "Please enter destination keystore file location : "
        dest = take_input(msg)
    else:
        dest = args.dest
    if not os.path.exists(dest):
        print(bcolors.FAIL + "The path entered for destination does not exist!!!" + bcolors.ENDC)
        sys.exit(2)

    if args.dest_passwd is None:
        msg = "Enter the destination keystore password"
        dest_passwd = getpass.getpass(bcolors.BOLD + msg + bcolors.ENDC + " : ")
    else:
        dest_passwd = args.dest_passwd

    try:
        subprocess.check_output(['keytool', '-list', '-keystore', dest, '-storepass', dest_passwd], stderr=subprocess.STDOUT)
    except Exception:
        print(bcolors.FAIL + "The password entered for destination Keystore is incorrect. Please check the password again" + bcolors.ENDC)
        print(bcolors.FAIL + "Use the command below to manually check the password" + bcolors.ENDC)
        print(bcolors.BOLD + "keytool -list -keystore <KEYSTORE_PATH> -storepass <PASSWORD>" + bcolors.ENDC)
        sys.exit(2)

    print(bcolors.BOLD + "Encypting the private key with keystore pass and storing in temporary file temp.key" + bcolors.ENDC)
    subprocess.check_output(
        ['openssl', 'rsa', '-in', 'temp_decr.key', '-aes256', '-out', 'temp.key', '-passout', 'pass:' + dest_passwd], stderr=subprocess.STDOUT)

    update_keystore_p12_update(source, dest, dest_passwd)



def update_keystore_cert(source):
    operation_on_flag = "cert"
    cert_file_handle = open(source,'r')
    cert_file_content = cert_file_handle.read()
    cert_file_handle.close()
    try:
        cert_decode = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,cert_file_content)
        cert_decode_content = cert_decode.get_subject().get_components()
    except:
        print(bcolors.FAIL + "Error reading the certificate. Check if the cert is valid" + bcolors.ENDC)
        print(bcolors.FAIL + "Use he command below" + bcolors.ENDC)
        print(bcolors.FAIL + "openssl x509 -in <Cert_file> -noout -text" + bcolors.ENDC)
        sys.exit(2)
    #Extract common name from source
    for i in range(len(cert_decode_content)):
        if cert_decode_content[i][0] == 'CN':
            common_name = cert_decode_content[i][1]

    expiry_date = parse(cert_decode.get_notAfter()).date()
    current_date = parse(str(datetime.datetime.now())).date()
    days_to_expiry = expiry_date - current_date

    if int(days_to_expiry.days) < 1:
        print(bcolors.FAIL + "The new certificate to be immported is expired." + bcolors.ENDC)
        print(bcolors.FAIL + "HELP - Use he command below to check for the expirey." + bcolors.ENDC)
        print(bcolors.FAIL + "openssl x509 -in <Cert_file> -noout -enddate" + bcolors.ENDC)
        sys.exit(2)

    if int(days_to_expiry.days) < 180:
        print(bcolors.WARNING + "The cert expires in less than 6 months approx." + bcolors.ENDC)

    if args.dest is None:
        msg = "Please enter destination keystore file location : "
        dest = take_input(msg)
    else:
        dest = args.dest
    if not os.path.exists(dest):
        print(bcolors.FAIL + "The path entered for destination does not exist!!!" + bcolors.ENDC)
        sys.exit(2)

    if args.alias is None:
        msg = "Please enter the alias name to be updated: "
        alias = take_input(msg)
    else:
        alias = args.alias

    if args.dest_passwd is None:
        msg = "Please enter the destination keystore password: "
        dest_passwd = getpass.getpass(bcolors.BOLD + msg + bcolors.ENDC + " : ")
    else:
        dest_passwd = args.dest_passwd

    try:
        subprocess.check_output(['keytool', '-list', '-keystore', dest, '-storepass', dest_passwd], stderr=subprocess.STDOUT)
    except Exception:
        print(bcolors.FAIL + "The password entered for destination Keystore is incorrect. Please check the password again" + bcolors.ENDC)
        print(bcolors.FAIL + "Use the command below to manually check the password" + bcolors.ENDC)
        print(bcolors.BOLD + "keytool -list -keystore <KEYSTORE_PATH> -storepass <PASSWORD>" + bcolors.ENDC)
        sys.exit(2)

    print(bcolors.BOLD + "Checking if the alias already exists!" + bcolors.ENDC)
    try:
        output = subprocess.check_output(
            ['keytool', '-list', '-v', '-alias', alias, '-keystore', dest, '-storepass', dest_passwd],
            stderr=subprocess.STDOUT)
    except Exception:
        print(bcolors.BOLD + "The alias entered does not exist. Adding a new Alias" + bcolors.ENDC)
        update_keystore_cert_add(alias, dest, dest_passwd, source)
    else:
        print(bcolors.BOLD + "Alias already exists. Replacing it now!" + bcolors.ENDC)
        update_keystore_cert_del_add(output, operation_on_flag, alias, dest, dest_passwd, source)


def update_keystore_cert_add(alias, dest, dest_passwd, source):
    try:
        subprocess.check_output(['keytool', '-import', '-alias', alias, '-keystore', dest, '-storepass', dest_passwd, '-trustcacerts', '-file', source, '-noprompt'], stderr=subprocess.STDOUT)
    except Exception:
        print(bcolors.FAIL + "Failed to add the new alias" + bcolors.ENDC)
        print(bcolors.FAIL + "Use the command below to manually delete the alias" + bcolors.ENDC)
        print(bcolors.BOLD + "keytool  -import -alias <ALIAS> -keystore <KEYSTORE_PATH> -storepass <PASSWORD> -trustcacert <SRC_PATH>" + bcolors.ENDC)
    print(bcolors.OKGREEN + "New Alias %s added successfully" % alias + bcolors.ENDC)


def update_keystore_cert_del_add(output, operation_on_flag, alias, dest, dest_passwd, source):
    try:
        subprocess.check_output(['keytool', '-delete', '-alias', alias, '-keystore', dest, '-storepass', dest_passwd], stderr=subprocess.STDOUT)
    except Exception:
        print(bcolors.FAIL + "This is weird and highly unlikely error" + bcolors.ENDC)
        print(bcolors.FAIL + "Use the command below to manually delete the alias" + bcolors.ENDC)
        print(bcolors.BOLD + "keytool  -delete -list -alias <ALIAS> -keystore <KEYSTORE_PATH> -storepass <PASSWORD>" + bcolors.ENDC)
        sys.exit(2)

    print(bcolors.OKGREEN + "Old Alias %s deleted successfully" % alias + bcolors.ENDC)
    print(bcolors.OKGREEN + "Details of the deleted alias" +bcolors.ENDC)
    print(bcolors.OKBLUE + output + bcolors.OKBLUE)
    if operation_on_flag == "cert":
        update_keystore_cert_add(alias, dest, dest_passwd, source)
    elif operation_on_flag == "p12":
        update_keystore_p12_add(alias, dest, dest_passwd)


def display_validate():
    operation = raw_input(bcolors.BOLD + msg + bcolors.ENDC)
    if operation not in valid_options:
        print(bcolors.FAIL + "incorrect option" + bcolors.ENDC)
        print(bcolors.BOLD + "Correct options are : %s" % valid_options + bcolors.ENDC )
        operation = display_validate()
    return operation


def update_keystore():
    if args.source is None:
        msg = "Please enter the source .p12/.pem/.crt file location : "
        source = take_input(msg)
    else:
        source = args.source
    if not os.path.exists(source):
        print(bcolors.FAIL + "The path entered does not exist!!!" + bcolors.ENDC)
        sys.exit(2)

    print(bcolors.BOLD + "The script currently supports only p12 and crt files to be imported" + bcolors.ENDC)
    print(bcolors.BOLD + "Checking if the source file is p12 or crt" + bcolors.ENDC)

    cert_file_handle = open(source,'r')
    cert_file_content = cert_file_handle.read()
    cert_file_handle.close()
    cert_count = re.findall(pattern="BEGIN CERTIFICATE", string=cert_file_content)
    if len(cert_count) == 0:
        update_keystore_p12_prep(source)
    elif len(cert_count) == 1:
        update_keystore_cert(source)
    else:
        print(bcolors.FAIL + "The certificate file has more than 1 entry" + bcolors.ENDC)
        print(bcolors.FAIL + "The script only supports keystore entry type 'trustedCertEntry' with 1 cert only" + bcolors.ENDC)
        sys.exit(2)


def delete_alias():
    if args.dest is None:
        msg = "Please enter destination keystore file location : "
        dest = take_input(msg)
    else:
        dest = args.dest
    if not os.path.exists(dest):
        print(bcolors.FAIL + "The path entered for destination does not exist!!!" + bcolors.ENDC)
        sys.exit(2)

    if args.dest_passwd is None:
        msg = "Enter the destination keystore password"
        dest_passwd = getpass.getpass(bcolors.BOLD + msg + bcolors.ENDC + " : ")
    else:
        dest_passwd = args.dest_passwd
    try:
        subprocess.check_output(['keytool', '-list', '-keystore', dest, '-storepass', dest_passwd], stderr=subprocess.STDOUT)
    except Exception:
        print(bcolors.FAIL + "The password entered is incorrect. Please check the password again" + bcolors.ENDC)
        print(bcolors.FAIL + "Use the command below to manually check the password" + bcolors.ENDC)
        print(bcolors.BOLD + "keytool -list -keystore <KEYSTORE_PATH> -storepass <PASSWORD>" + bcolors.ENDC)
        sys.exit(2)

    if args.alias is None:
        msg = "Please enter the alias to be deleted : "
        alias = take_input(msg)
    else:
        alias = args.alias
    try:
        output = subprocess.check_output(
            ['keytool', '-list', '-v', '-alias', alias, '-keystore', dest, '-storepass', dest_passwd],
            stderr=subprocess.STDOUT)
    except Exception:
        print(bcolors.FAIL + "The alias entered does not exist. Please check the alias again" + bcolors.ENDC)
        print(bcolors.FAIL + "Use the command below to manually check the alias" + bcolors.ENDC)
        print(bcolors.BOLD + "keytool -list -alias <ALIAS> -keystore <KEYSTORE_PATH> -storepass <PASSWORD>" + bcolors.ENDC)
        sys.exit(2)
    else:
        print(bcolors.BOLD + "Alias details to be deleted" + bcolors.ENDC)
        print(bcolors.OKBLUE + output + bcolors.ENDC)

    try:
        subprocess.check_output(['keytool', '-delete', '-alias', alias, '-keystore', dest, '-storepass', dest_passwd], stderr=subprocess.STDOUT)
    except Exception:
        print(bcolors.FAIL + "This is weird and highly unlikely error" + bcolors.ENDC)
        print(bcolors.FAIL + "Use the command below to manually delete the alias" + bcolors.ENDC)
        print(bcolors.BOLD + "keytool  -delete -list -alias <ALIAS> -keystore <KEYSTORE_PATH> -storepass <PASSWORD>" + bcolors.ENDC)
        sys.exit(2)
    print(bcolors.OKGREEN + "Alias %s deleted successfully" % alias + bcolors.ENDC)



parser = argparse.ArgumentParser()
parser.add_argument("-s","--source", help="The source .p12/.pem/.crt file which needs to be updated/added. Please instead use --sep_cert_file and --sep_key_file in case of sep_cert_key_file_update operations")
parser.add_argument("-d", "--dest", help="The destination keystore path")
parser.add_argument("-o","--operation", choices=['update', 'delete', 'sep_cert_key_file_update'], help="'delete' (to delete cert from keystore) \
 'update' (to add / update the cert in keystore) 'sep_cert_key_file_update' (To add cert and key as separate files)")
parser.add_argument("--src_passwd", help="password of the source p12 file to be updated")
parser.add_argument("--dest_passwd", help="password of the destination keystore to be udpated")
parser.add_argument("-a", "--alias", help="alias to be updated/deleted")
parser.add_argument("--sep_cert_file", help="Should be used with operation type sep_cert_key_file_update to specify the cert file")
parser.add_argument("--sep_key_file", help="Should be used with operation type sep_cert_key_file_update to specify the key file")
args = parser.parse_args()

valid_options = ["update", "delete", "sep_cert_key_file_update"]

if args.operation is None:
    msg = "Please enter the operation you want %s : " % valid_options
    operation = display_validate()
else:
    operation = args.operation

readline.parse_and_bind("tab: complete")

if operation == "update":
    update_keystore()
elif operation == "delete":
    delete_alias()
else:
    update_keystore_sep()
