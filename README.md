# keystore-update
To add individual crt/p12 files to keystore
Just execute without any commands to get started. Script is interactive.
Also the command line options can be used to run in non interactive mode.
```
python keystore_update.py -h
usage: keystore_update.py [-h] [-s SOURCE] [-d DEST]
                          [-o {update,delete,sep_cert_key_file_update}]
                          [--src_passwd SRC_PASSWD]
                          [--dest_passwd DEST_PASSWD] [-a ALIAS]
                          [--sep_cert_file SEP_CERT_FILE]
                          [--sep_key_file SEP_KEY_FILE]

optional arguments:
  -h, --help            show this help message and exit
  -s SOURCE, --source SOURCE
                        The source .p12/.pem/.crt file which needs to be
                        updated/added. Please instead use --sep_cert_file and
                        --sep_key_file in case of sep_cert_key_file_update
                        operations
  -d DEST, --dest DEST  The destination keystore path
  -o {update,delete,sep_cert_key_file_update}, --operation {update,delete,sep_cert_key_file_update}
                        'delete' (to delete cert from keystore) 'update' (to
                        add / update the cert in keystore)
                        'sep_cert_key_file_update' (To add cert and key as
                        separate files)
  --src_passwd SRC_PASSWD
                        password of the source p12 file to be updated
  --dest_passwd DEST_PASSWD
                        password of the destination keystore to be udpated
  -a ALIAS, --alias ALIAS
                        alias to be updated/deleted
  --sep_cert_file SEP_CERT_FILE
                        Should be used with operation type
                        sep_cert_key_file_update to specify the cert file
  --sep_key_file SEP_KEY_FILE
                        Should be used with operation type
                        sep_cert_key_file_update to specify the key file
```
