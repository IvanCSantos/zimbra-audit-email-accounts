#!/bin/bash
# Desenvolvido por: Ivan Santos - Nuxstep
# ivan.santos@nuxstep.com
# Em: 05/02/2024
# Rev.: 01

# Script for security analysis of email accounts in the Zimbra Collaboration Suite Open Source Edition (ZCS OSE)

email_accounts='email_list.txt'
export_dir='./sec_report'
log="${export_dir}/sec_report_log.txt"
auditlog='/opt/zimbra/log/audit.log'
zimbralog='/var/log/zimbra'

# Create directories to store the reports
echo "$(date +%d/%m/%Y-%H:%M:%S): Criando diretorio ${export_dir} para armazenamento dos logs recuperados." | tee -a ${log}
[ ! -d ${export_dir} ] && mkdir -p ${export_dir}
echo "$(date +%d/%m/%Y-%H:%M:%S): Criando diretorio ${export_dir}/log-files para armazenamento dos arquivos originais consultados." | tee -a ${log}
[ ! -d ${export_dir}/log-files ] && mkdir -p ${export_dir}/log-files
[ ! -d ${export_dir}/log-files/audit-log ] && mkdir -p ${export_dir}/log-files/audit-log
[ ! -d ${export_dir}/log-files/zimbra-log ] && mkdir -p ${export_dir}/log-files/zimbra-log

cp ${auditlog}* ${export_dir}/log-files/audit-log
cp ${zimbralog}* ${export_dir}/log-files/zimbra-log

for email in $(cat ${email_accounts}); do

  # String email to lower
  email=$(echo ${email} | awk '{print tolower($0)}')

  # Defining the account to be analyzed
  account=`echo ${email} | cut -f1 -d"@"`
  account=$(echo ${account} | awk '{print tolower($0)}')
  echo "$(date +%d/%m/%Y-%H:%M:%S): Iniciando analise da conta ${account}." | tee -a ${log}

  # Creating a directory to store the recovered logs
  echo "$(date +%d/%m/%Y-%H:%M:%S): Criando diretorio (${export_dir}/${account}) para logs da conta ${account}." | tee -a ${log}
  [ ! -d ${export_dir}/${account} ] && mkdir -p ${export_dir}/${account}
  stat=$(echo $?)
  if [ ${stat} -eq 0 ]
  then
    echo "$(date +%d/%m/%Y-%H:%M:%S): Criação do diretório ${export_dir}/${account} realizada com êxito." | tee -a $log
  else
    echo "$(date +%d/%m/%Y-%H:%M:%S): Criação do diretório ${export_dir}/${account} falhou!" | tee -a $log
  fi
  
  # Recupera status da conta
  echo "$(date +%d/%m/%Y-%H:%M:%S): Verificando status da conta ${account}." | tee -a ${log}
  acc_status=`zmprov ga ${email} zimbraAccountStatus | grep -v ^# | cut -d" " -f2`
  echo "Status atual da conta: ${acc_status}" tee -a ${export_dir}/${account}/${account}_account-status.txt
  echo "$(date +%d/%m/%Y-%H:%M:%S): Status da conta ${account} é: ${acc_status}" | tee -a ${log}

  # Recupera data de último login da conta
  echo "$(date +%d/%m/%Y-%H:%M:%S): Verificando data do último login da conta ${account}." | tee -a ${log}
  dt_last_login=`zmprov ga ${email} zimbraLastLogonTimestamp | grep -v ^# | cut -d" " -f2`
  echo "Timestamp do último login no webmail: ${dt_last_login}" | tee -a ${export_dir}/${account}/${account}_last-login-on-webmail.txt
  echo "$(date +%d/%m/%Y-%H:%M:%S): Data do último login no webmail da conta ${account} é: ${dt_last_login}" | tee -a ${log}
  
  # Recupera data de alteração de senha da conta
  echo "$(date +%d/%m/%Y-%H:%M:%S): Verificando data de alteração de senha da conta ${account}." | tee -a ${log}
  dt_pw_change=`zmprov sa -v "mail=${email}" | egrep '^mail:|zimbraPasswordModifiedTime:|^$' | grep zimbraPasswordModifiedTime | cut -d" " -f2`
  echo "Timestamp da última alteração de senha: ${dt_pw_change}" | tee -a ${export_dir}/${account}/${account}_pw-change.txt
  echo "$(date +%d/%m/%Y-%H:%M:%S): Data da última alteração de senha da conta ${account} é: ${dt_pw_change}" | tee -a ${log}
  
  # Recupera configuração de encaminhamento de mensagens da conta
  echo "$(date +%d/%m/%Y-%H:%M:%S): Verificando configurações de encaminhamento da conta ${account}." | tee -a ${log}
  forwarding=`zmprov ga $email zimbraPrefMailForwardingAddress | grep -v ^# | cut -d: -f 2`
  echo "Configuração de encaminhamento: ${forwarding}" | tee -a ${export_dir}/${account}/${account}_forwarding.txt
  echo "$(date +%d/%m/%Y-%H:%M:%S): Configuração de encaminhamento da conta ${account} é: ${forwarding}" | tee -a ${log}

  # Recupera logs de acesso (audit.log)
  echo "$(date +%d/%m/%Y-%H:%M:%S): Verificando logs de acesso da conta ${account}." | tee -a ${log}
  zcat ${auditlog}* | egrep "account=${email}" | tee -a ${export_dir}/${account}/${account}_audit.txt
  echo "$(date +%d/%m/%Y-%H:%M:%S): Logs de acesso do audit.log foram salvos em ${export_dir}/${account}/${account}_audit.txt." | tee -a ${log}
  
  # Recupera logs de acesso (audit.log) em que não ocorreu falha
  echo "$(date +%d/%m/%Y-%H:%M:%S): Verificando logs de acesso com sucesso da conta ${account}." | tee -a ${log}
  echo "Apenas logs de acesso com sucesso da conta ${account}:" | tee -a ${export_dir}/${account}/${account}_audit-login-successfully.txt
  zcat ${auditlog}* | egrep "account=${email}" | egrep -v 'authentication failed|error=account lockout' | tee -a ${export_dir}/${account}/${account}_audit-login-successfully.txt
  echo "$(date +%d/%m/%Y-%H:%M:%S): Logs de acesso com sucesso do audit.log foram salvos em ${export_dir}/${account}/${account}_audit-login-successfully.txt." | tee -a ${log}
  echo "$(date +%d/%m/%Y-%H:%M:%S): Gerando resumo de endereços IPs autenticados com sucesso" | tee -a ${log}
  for line in $(cat ${export_dir}/${account}/${account}_audit-login-successfully.txt); do
    echo $line | sed -n 's/.*oip=//p' | sed -n 's/;.*//p' | tee -a ${export_dir}/${account}/${account}_audit-login-successfully-IPs-temp.txt;
  done
  echo "Endereços IP distintos que realizaram login com sucesso: (Total, IP):" | tee -a ${export_dir}/${account}/${account}_audit-login-successfully-IPs.txt
  cat ${export_dir}/${account}/${account}_audit-login-successfully-IPs-temp.txt | sort | uniq -c | sort -nr | tee -a ${export_dir}/${account}/${account}_audit-login-successfully-IPs.txt
  rm -f ${export_dir}/${account}/${account}_audit-login-successfully-IPs-temp.txt
  echo "$(date +%d/%m/%Y-%H:%M:%S): Resumo de endereços IPs autenticados com sucesso salvo em ${export_dir}/${account}/${account}_audit-login-successfully-IPs.txt" | tee -a ${log}

  # Recupera mensagens enviadas pelo usuário
  echo "$(date +%d/%m/%Y-%H:%M:%S): Verificando mensagens enviadas pela conta ${account}." | tee -a ${log}
  /opt/zimbra/libexec/zmmsgtrace -s ${email} ${zimbralog}* | tee -a ${export_dir}/${account}/${account}_sent.txt
  echo "$(date +%d/%m/%Y-%H:%M:%S): Logs de envio foram salvos em ${export_dir}/${account}/${account}_sent.txt." | tee -a ${log}
  
  # Recupera mensagens recebidas pelo usuário
  echo "$(date +%d/%m/%Y-%H:%M:%S): Verificando mensagens recebidas pela conta ${account}." | tee -a ${log}
  /opt/zimbra/libexec/zmmsgtrace -r ${email} ${zimbralog}* | tee -a ${export_dir}/${account}/${account}_received.txt
  echo "$(date +%d/%m/%Y-%H:%M:%S): Logs de recebimento foram salvos em ${export_dir}/${account}/${account}_received.txt." | tee -a ${log}
done

# Recuperando estatisticas de envio de e-mail atraves de autenticação SASL
echo "$(date +%d/%m/%Y-%H:%M:%S): Verificando estatisticas de mensagens enviadas - total por usuário SASL." | tee -a ${log}
zcat /var/log/zimbra.log* | sed -n 's/.*sasl_username=//p' | sort | uniq -c | sort -nr | tee -a ${export_dir}/sent_messages_by_sasl_user.txt
echo "$(date +%d/%m/%Y-%H:%M:%S): Logs de envio de mensagens por usuário SASL foram salvos em ${export_dir}/sent_messages_by_sasl_user.txt." | tee -a ${log}