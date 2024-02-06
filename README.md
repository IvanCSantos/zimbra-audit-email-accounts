# zimbra-audit-email-accounts
Script for security analysis of email accounts in the Zimbra Collaboration Suite Open Source Edition (ZCS OSE)

I developed this script to help me with the task of analyzing suspicious activity in a list of ZCS OSE accounts. Please feel free to contribute suggestions and updates to the script.

## How to use it
You must connect to the server that is running the Zimbra application, and use the zimbra user (`su - u zimbra`).

Fill in the email_list.txt file with the list of accounts you want to analyze, one account per line. You can use the following format: `user@domain.com`

If you want to check all users on the server, you can still update the list with the command below:
`zmprov -l gaa | tee -a email_list.txt`

Once you have the `email_list.txt` file with the list of accounts you want to check, simply run the `audit-email-accounts.sh` script:
```
./audit-email-accounts.sh
```

Once the script finishes executing, it will have generated a directory called `sec_report` in the current directory with the relevant logs for account audit analysis.

### For convenience, the script generates information in separate files to easily locate:

- Account status: `sec_report/$account/$account__account-status.txt`
- Timestamp of last webmail login: `sec_report/$account/$account__last-login-on-webmail.txt`
- Timestamp of last password change: `sec_report/$account/$account__pw-change.txt`
- Account forwarding settings: `sec_report/$account/$account__forwarding.txt`
- Access attempt logs: `sec_report/$account/$account__audit.txt`
- Successful login logs: `sec_report/$account/$account__audit-login-successfully.txt`
- IP addresses where successful login was recorded: `sec_report/$account/$account__audit-login-successfully-IPs.txt`
- Messages sent by the user: `sec_report/$account/$account__sent.txt`
- Messages received by the user: `sec_report/$account/$account__received.txt`
- A general log of messages sent `using SASL authentication (all server users): sec_report/sent_messages_by_sasl_user.txt`

Additionally, to ensure that the original log records used are maintained so that it is possible to continue analyzing them as long as necessary (as log rotation will soon delete them), a copy of the original logs is maintained in `sec_report/log-files`.