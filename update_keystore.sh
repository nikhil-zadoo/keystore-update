#!/bin/bash
#Author - nikhil.zadoo@gmail.com
#Version - 1.0
##############	functions  #######################
function check_command_status () {
	if [ $? -ne 0 ]; then
		echo -e "$1"
		exit
	fi
}

function delete_cert () {
        msg="\t\e[1;31mEnter the alias you want to delete \e[0m"
        take_input "$msg"
        dest_alias=$choice

        msg="\t\e[1;31mEnter the keystore file path to update \e[0m"
        take_input "$msg"
        dest_path=$choice

        if [ ! -f $dest_path ]; then
                echo -e "\t\e[1;31mThe destination keystore does not exist \e[0m"
                exit
        fi

        msg="\t\e[1;31mEnter the destination password. Dont worry if you are sharing screen, the password will not be displayed \e[0m"
        take_input_secret "$msg"
        dest_pass=$secret

	echo -e "\t\e[1;31mDeleting the present alias - $dest_alias \e[0m"
        echo $dest_pass | keytool -delete -alias $dest_alias -keystore $dest_path
	check_command_status "\n\t\e[1;31mIssue while deleting the cert.\n\tCheck the credentials and Alias. Use - \n\tkeytool -list -alias <alias> -keystore <dest_keystore_file> \e[0m"
}

function take_input_secret () {
	echo -e "$1 \e[0m"
	stty -echo
	read secret
	stty echo
}

function take_input () {
        echo -e "$1"
        read choice
}

function continue_input () {
	echo -e "$1"
	read choice
	case "$choice" in
		yes)
			echo -e "\t\e[1;31mContinuing!! \e[0m"
		;;
		no)
			echo -e "\t\e[1;31mExiting!! Nothing has been updated to the destination keystore!! \e[0m"
			exit
		;;
		*)
			echo -e "\t\e[1;31mPlease Enter a valid choice \e[0m"
			continue_input "$1"
		;;
	esac
	
}

function keytool_export () {
	echo -e "\t\e[1;31mChecking if the credentials for destination Keystore are okay \e[0m"
	temp_output=$(echo $dest_pass | keytool -list -keystore $dest_path)
	check_command_status "\n\t\e[1;31mIssue with the credentials provided for the destination keystore.\
				\n\tUse following command manually to debug issue\n\tkeytool -list -keystore <dest_keystore_file> \e[0m"

	echo -e "\t\e[1;31mTaking backup of current destination keystore. the backup will be stored in the current working directory with the name <keystore_name>_bkp \e[0m"
	cp $dest_path $dest_path"_bkp"
	check_command_status "\n\t\eIssue while taking backup. Check if you have correct permissions on the current directory \e[0m"
	
	echo -e "\t\e[1;31mChecking if the alias is already present in the destination Keystore \e[0m"
	dest_out=$(echo $dest_pass | keytool -list -v -alias $dest_alias -keystore $dest_path)
	echo $dest_out | grep "does not exist"

	if [ "$?" -ne "0" ]; then
		echo -e "\t\e[1;31mComparing the existing entry and the new alias for any mismatch \e[0m"
		dest_alias_chain=$(echo $dest_out | sed 's/.*Certificate chain length\: \(.*\) Certificate\[.*/\1/')
		if [ $dest_alias_chain != $src_alias_chain ]; then
			msg="\t\e[1;31mThere seems to be a mismatch in the new p12 cert chain length and the existing alias in the destination keystore\
			\n\tDo you still want to continue? Please continue only if you are completely sure\n\t(yes/no) \e[0m"
			continue_input "$msg"
		fi
		echo -e "\t\e[1;31mDeleting the present alias - $dest_alias \e[0m"
		echo $dest_pass | keytool -delete -alias $dest_alias -keystore $dest_path
	fi

	echo -e "\t\e[1;31mAdding the p12 file to keystore \e[0m"
	keytool -importkeystore -srckeystore temp.p12 -destkeystore $dest_path -srcstoretype PKCS12 -deststoretype JKS \
	-srcalias $src_alias -destalias $dest_alias -deststorepass $dest_pass -srcstorepass $dest_pass

	echo -e "\t\e[1;31mDetails of the new certificate/key pair added \e[0m"
	echo $dest_pass | keytool -list -v -alias $dest_alias -keystore $dest_path
}

function p12prep () {
	echo -e "\t\e[1;31mCleaning up old temp certs and keys that might have stayed after last run \e[0m"
	rm tempCL.crt tempCA.crt temp.key temp.p12

	echo -e "\t\e[1;31mExtracting the Client certificate \e[0m"
	openssl pkcs12 -clcerts -nokeys -in $src_path -out tempCL.crt -passin pass:$src_pass
	check_command_status "\n\t\eIssue while trying to extract Client cert.\n\tuse following command manually to debuf issue\
				\n\topenssl pkcs12 -clcerts -nokeys -in <src_p12_file> -out tempCL.crt -passin pass:<src_keystore_password> \e[0m"

	echo -e "\t\e[1;31mExtracting the Client CA certificate \e[0m"
	openssl pkcs12 -cacerts -nokeys -in $src_path -out tempCA.crt -passin pass:$src_pass
	check_command_status "\n\t\eIssue while trying to extract Client CA cert.\n\tuse following command manually to debuf issue\
				\n\topenssl pkcs12 -cacerts -nokeys -in <src_p12_file> -out tempCL.crt -passin pass:<src_keystore_password> \e[0m"

	cat tempCL.crt tempCA.crt > temp.crt

	echo -e "\t\e[1;31mExtracting the Key \e[0m"
	openssl pkcs12 -nocerts -in $src_path -out temp.key -passin pass:$src_pass -passout pass:$dest_pass
	check_command_status "\n\t\eIssue while Extracting the key. Use the following command manually to debug\
				\n\topenssl pkcs12 -nocerts -in <source_p12_file> -out temp.key -passin pass:<src_p12_passwd> -passout pass:<dest_p12_passwd> \e[0m"

	echo -e "\t\e[1;31mChecking if the password on the key to be exported is set properly \e[0m"
	openssl rsa -in temp.key -noout -passin pass:$dest_pass
	check_command_status "\n\t\eIncorrect password set on the extracted key from source. Use the following command manually to debug\
				\n\topenssl pkcs12 -nocerts -in <source_p12_file> -out temp.key -passin pass:<src_p12_passwd> -passout pass:<dest_p12_passwd> \e[0m"
	
	echo -e "\t\e[1;31mCreating new p12 file for exporting \e[0m"
	openssl pkcs12 -export -in temp.crt -inkey temp.key -name $dest_alias -out temp.p12 -passin pass:$dest_pass -passout pass:$dest_pass

	keytool_export
}

function p12import () {
	msg="\t\e[1;31mEnter the path \
	of the source p12 file \e[0m"
	take_input "$msg"
	src_path=$choice

        if [ ! -f $src_path ]; then
                echo -e "\t\e[1;31mThe source p12 file does not exist \e[0m"
                exit
        fi

        msg="\t\e[1;31mEnter tha path of the destination keystore file \e[0m"
        take_input "$msg"
        dest_path=$choice

        if [ ! -f $dest_path ]; then
                echo -e "\t\e[1;31mThe destination keystore does not exist \e[0m"
                exit
        fi

        msg="\t\e[1;31mEnter the destination alias \e[0m"
        take_input "$msg"
        dest_alias=$choice

        msg="\t\e[1;31mEnter the source password. Dont worry if you are sharing screen, the password will not be displayed \e[0m"
	take_input_secret "$msg"
	src_pass=$secret

        msg="\t\e[1;31mEnter the destination password. Dont worry if you are sharing screen, the password will not be displayed \e[0m"
        take_input_secret "$msg"
        dest_pass=$secret

	out=$(echo $src_pass | keytool -list -v -keystore $src_path)
	if [ $? -ne 0 ]; then
		echo -e "\n\t\e[1;31mThe source p12 file is not readable. please check the password again or check if the file is tampered with.\
			\n\tuse the manual command to check 'keytool -list -v -keystore <file_name>' \e[0m"
		exit
	fi
	echo -e "\n \e[0m"
	num_certs=$(echo $out | sed 's/.*Your keystore contains \([0-9]*\) entry.*/\1/g')

	if [ "$num_certs" -ne "1" ]; then
		echo -e "\t[1;31mThe script only supports adding 1 cert at a time. the source file contains more than 1 \e[0m"
		exit
	fi

	cert_type=$(echo $out | sed 's/.*type\: \(.*\) Certificate chain.*/\1/')
	if [ "$cert_type" != "PrivateKeyEntry" ]; then
		echo -e "\t[1;31mThe certificate doesnt seem to have a key attached. please use option 2 in this case! \e[0m"
		exit
	fi

	src_alias_chain=$(echo $out | sed 's/.*Certificate chain length\: \(.*\) Certificate\[.*/\1/')
	src_alias=$(echo $out | sed 's/.*Alias name\: \(.*\) Creation date.*/\1/')

	p12prep
}

function certimport () {
        echo "Inside cert function \e[0m"
}

function start_execution () {
msg="\t\e[1;31mWhat action do you want to perform?\
	\n\t1 -> Add/Replace P12 file (PrivateKeyEntry -> CERT + KEY)\
	\n\t2 -> P12/Cert file (trustedCertEntry -> Only cert. No key) \
	\n\t3 -> Delete cert \e[0m"
take_input "$msg \e[0m"
case $choice in
  1)
        p12import
        ;;
  2)
        certimport
        ;;
  3)
	delete_cert
	;;
  *)
        echo -e "\t[1;31mIncorrect choice. please enter valid choice \e[0m"
	start_execution
        ;;
esac

}
##############  functions end  #######################

##############  Execution starts  #######################

start_execution
