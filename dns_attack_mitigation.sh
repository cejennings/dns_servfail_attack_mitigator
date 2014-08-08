#!/bin/bash

#: Title       : dns_servfail_attack_mitigator.sh
#:             : (c) 2014, Charles Jennings, released under GPLv2
#: Date Created: Feb 17, 2014
#: Last Edit   : Jun 02, 2014
#: Author      : Charles Jennings
#:             : ( cejennings_cr {@} yahoo.com )
#: Version     : 0.3.1 (20140602)
#: Description : This script will take a snapshot of the last 
#                SERVFAIL errors logged by BIND named as defined by 
#                certain limits below.  The script will then evaluate 
#                all the different IP addresses making queries and
#                the domains that are being queried and, based on 
#                weighting rules below, will make a determination if
#                a domain should be blocked with iptables.  By 
#                default this script will alert only, but the script
#                can be enabled to automatically block domains found
#                to be under attack.
#                During non-attack periods, if configured to auto-
#                block, the script will check for expired rules,
#                based on the configured timeframe, and remove rules.
#
#                Configuration Options:
#                The script will look for its default file at: 
#                   /etc/dns_servfail_attack_mitigator.conf
#                you can provide a user configuration file using:
#                   -c user_supplied_config_file
#                The config file MUST have 600 permissions and be
#                owned by the user running the script (root in most
#                cases).
#                If no file found, the default options here listed
#                will be used:
#
#                report_only_flag:            1
#                mitigate_attack:             0
#                summarize_report:            1
#                email_subject_report_only:   "`hostname` under DNS SERVFAIL attack - Report Only - No Mitigation actions taken"
#                email_subject_mitigated:     "`hostname` under DNS SERVFAIL attack - Mitigation has occured"
#                email_subject_rule_cleanup:  "`hostname` DNS SERVFAIL attack - iptables Rule Cleanup has occured"
#                email_destination:           "jdoe@example.com,john.doe@example.com"
#                named_debug_log_file:        /chroot/named/logs/dns_limiting.log
#                named_debug_log_file0:       /chroot/named/logs/dns_limiting.log.0
#                max_records:                 15000
#                max_time:                    300
#                column_of_ip_addr:           7
#                column_of_fqdn:              12
#                ip_qpm_heavy_rate:           60
#                ip_qpm_midweight_rate:       40
#                ip_qpm_light_rate:           20
#                min_mal_ip_per_domain:       5
#                block_trigger_value:         15
#                iptables_chain:              "INPUT"
#                block_removal:               48

#####################################################################
###               Do Not Edit Below This Line                     ###
#####################################################################
##

if [[ $1 == -c ]]; then
    CONFIG_FILE=$2
else
    CONFIG_FILE=/etc/dns_servfail_attack_mitigator.conf
fi

if [[ -f $CONFIG_FILE ]]; then
    if [[ -O $CONFIG_FILE ]]; then
        if [[ $(stat --format %a $CONFIG_FILE) == 600 ]]; then
            . $CONFIG_FILE
        else
            echo "Configuration file MUST have 600 rights - exiting script"
            exit 9
        fi
    else
        echo "Configuration file MUST be owned by effective user (root) - exiting script"
        exit 8
    fi
else
    echo "No configuration file found or specified - using default values"
fi

## - Configuration Option Defaults:

let report_only_flag=${report_only_flag:-1}
let mitigate_attack=${mitigate_attack:-0}
let summarize_report=${summarize_report:-1}
email_subject_report_only=${email_subject_report_only:-"`hostname` under DNS SERVFAIL attack - Report Only - No Mitigation actions taken"}
email_subject_mitigated=${email_subject_mitigated:-"`hostname` under DNS SERVFAIL attack - Mitigation has occured"}
email_subject_rule_cleanup=${email_subject_rule_cleanup:-"`hostname` DNS SERVFAIL attack - iptables Rule Cleanup has occured"}
email_destination=${email_destination:-"jdoe@example.com,john.doe@example.com"}
named_debug_log_file=${named_debug_log_file:-/chroot/named/logs/dns_limiting.log}
named_debug_log_file0=${named_debug_log_file0:-/chroot/named/logs/dns_limiting.log.0}
let max_records=${max_records:-15000}
let max_time=${max_time:-300}
let column_of_ip_addr=${column_of_ip_addr:-7}
let column_of_fqdn=${column_of_fqdn:-12}
let ip_qpm_heavy_rate=${ip_qpm_heavy_rate:-60}
let ip_qpm_midweight_rate=${ip_qpm_midweight_rate:-40}
let ip_qpm_light_rate=${ip_qpm_light_rate:-20}
let min_mal_ip_per_domain=${min_mal_ip_per_domain:-5}
let block_trigger_value=${block_trigger_value:-15}
iptables_chain=${iptables_chain:-"INPUT"}
let block_removal=${block_removal:-48}

##

mailit () {
        echo "# End: `date` #" >> $emailmessage
        let mail_address_count=`echo $1 | gawk -F, '{ print NF }'`
        for (( y =1 ; y <= mail_address_count ; y++ )); do
                destmail=`echo $1 | gawk -F, -v yy=$y '{ print $yy }'`
                /bin/mail -s "$2" "$destmail" < $emailmessage
        done
}

spaceit () {
        let spaceitcounter=$1
        until [ $spaceitcounter = 0 ]; do
                printf " " >> $emailmessage
                let spaceitcounter=$spaceitcounter-1
        done
        let spaceitcounter=0
}

populatearrays () {
        #------------
        workingfile=$(mktemp)
        workingfile2=$(mktemp)
        tac $named_debug_log_file $named_debug_log_file0 > $workingfile
        sed -n -e '/SERVFAIL/p' $workingfile | sed -e '/\!/d' > $workingfile2
        sed -i -e 's/\\032/ /g' $workingfile2
        oldifs=$IFS
        IFS=$'\n'
        let i=0
        let ii=0
        #------------
        echo "# Start: `date` #" > $emailmessage
        echo "# Start: `date` #" > $summaryemail
        echo "Populating Arrays" >> $emailmessage
        echo "" >> $emailmessage
        echo "  (each # represents 100 records)" >> $emailmessage
        while read value
        do
                item_date=`echo $value | gawk '{ print $1}'`
                item_time=`echo $value | gawk '{ print $2}'`
                let item_epoch=`date --date "$item_date $item_time" +%s`
                let temp_epoch=$item_epoch
                item_ip[$i]=`echo $value | gawk -v xx=$column_of_ip_addr '{ print $xx }' | cut -d\# -f1`
                item_domain[$i]=`echo $value | gawk -v xx=$column_of_fqdn '{ print $xx }' | cut -d\/ -f1`
                let item_domain_depth[$i]=`echo ${item_domain[$i]} | gawk -F. '{ print NF }'`
                if [ ${item_domain_depth[$i]} -gt 2 ]; then
                        if [ $item_epoch -gt $time_trigger ]; then
                                let i=$i+1
                        fi
                fi
                let z=$i%100
                let ii=$ii+1
                let iii=$i+100
                if [ $z = 0 ]; then
                        printf "#" >> $emailmessage
                fi
                if [ $i -gt $max_records ]; then
                        break
                fi
                if [ $iii -lt $ii ]; then
                        break
                fi
        done < $workingfile2
        printf "\n" >> $emailmessage
        let timecaptured=$current_epoch-$temp_epoch
        let ip_heavy_rate=$timecaptured*$ip_qpm_heavy_rate/60
        let ip_midweight_rate=$timecaptured*$ip_qpm_midweight_rate/60
        let ip_light_rate=$timecaptured*$ip_qpm_light_rate/60
        let domain_heavy_rate=$timecaptured*$ip_qpm_heavy_rate*$min_mal_ip_per_domain/60
        let domain_midweight_rate=$timecaptured*$ip_qpm_midweight_rate*$min_mal_ip_per_domain/60
        let domain_light_rate=$timecaptured*$ip_qpm_light_rate*$min_mal_ip_per_domain/60
        echo >> $emailmessage
        echo "Time Captured:               $timecaptured seconds" >> $emailmessage
        echo "Heavy IP Rate:               $ip_heavy_rate total hits in this timeframe ($ip_qpm_heavy_rate hits per minute per 1 IP)" >> $emailmessage
        echo "Mid-weight IP Rate:          $ip_midweight_rate total hits in this timeframe ($ip_qpm_midweight_rate hits per minute per 1 IP)" >> $emailmessage
        echo "Light IP Rate:               $ip_light_rate total hits in this timeframe ($ip_qpm_light_rate hits per minute per 1 IP)" >> $emailmessage
        echo "Heavy Domain-IP Rate:        $domain_heavy_rate total hits in this timeframe ($ip_qpm_heavy_rate times $min_mal_ip_per_domain hits per minute)" >> $emailmessage
        echo "Mid-weight Domain-IP Rate:   $domain_midweight_rate total hits in this timeframe ($ip_qpm_midweight_rate times $min_mal_ip_per_domain hits per minute)" >> $emailmessage
        echo "Light Domain-IP Rate:        $domain_light_rate total hits in this timeframe ($ip_qpm_light_rate times $min_mal_ip_per_domain hits per minute)" >> $emailmessage
        #------------
        let i=0
        value=""
        let ii=0
        IFS=$oldifs
        rm -f $workingfile
        rm -f $workingfile2
}

check_weight () {
        if [ $working_domain_count -gt $domain_heavy_rate ]; then
                let working_domain_weight=3
        else 
                if [ $working_domain_count -gt $domain_midweight_rate ]; then
                        let working_domain_weight=2
                else    
                        if [ $working_domain_count -gt $domain_light_rate ]; then
                                let working_domain_weight=1
                        fi
                fi
        fi
        if [ $working_domain_weight -gt 0 ]; then
                let prev_domain_hit_flag=1
                domain_count[$i]=$working_domain_count
                domain_name[$i]=`echo $value | gawk '{ print $2 }'`
                domain_weight[$i]=$working_domain_weight
                let ip_to_domain_ptr[$y]=$i
                ip_to_domain_ip[$y]="$working_ip"
                let ip_to_domain_count[$y]=$working_domain_per_ip_count
                let ip_total_weight[$y]=${ip_weight[$z]}
                let y=$y+1
        fi
}

increase_pointer () {
        if [ "$new_domain_flag" = "1" ]; then
                if [ "$prev_domain_hit_flag" = "1" ]; then
                        let i=$i+1
                        let new_domain_flag=0
                        let prev_domain_hit_flag=0
                        let working_domain_weight=0
                fi
        fi
}

evaluate_hits () {
        echo >> $emailmessage
        echo "Beginning Evaluation" >> $emailmessage
        echo >> $emailmessage
        echo "--- Dropping hostpart from FQDN" >> $emailmessage
        echo >> $emailmessage
        let counter=${#item_domain[@]}
        for (( i = 0 ; i < counter ; i++ )); do
                domain_working=""
                temp=""
                let y=${item_domain_depth[$i]}-2
                until [ $y -lt 0 ]; do
                        temp=`echo ${item_domain[$i]} | gawk -F. -v yy=$y '{ print $(NF-yy) }'`
                        domain_working=$domain_working$temp
                        if [ $y != 0 ]; then
                                domain_working=$domain_working"."
                        fi
                        let y=$y-1
                done;
                item_domain_sans_hostpart[$i]=$domain_working
                let z=$i%100
                if [ $z = 0 ]; then
                        printf "#" >> $emailmessage
                fi
        done;
        printf "\n" >> $emailmessage
        #------------
        let i=0
        let y=0
        domain_working=""
        temp=""
        #------------
        echo >> $emailmessage
        echo "--- Sort by Domain and Sort by IP Address" >> $emailmessage
        echo >> $emailmessage
        #------------
        domainsortfile=$(mktemp)
        domainsortedfile=$(mktemp)
        ipsortfile=$(mktemp)
        ipsortedfile=$(mktemp)
        for (( i = 0 ; i < counter ; i++ )); do
                echo "${item_domain_sans_hostpart[$i]} ${item_ip[$i]}" >> $domainsortfile
                printf "${item_ip[$i]}\n" >> $ipsortfile
        done
        sort $domainsortfile > $domainsortedfile
        sort $ipsortfile > $ipsortedfile
        #------------
        unset item_ip
        unset item_domain
        unset item_domain_depth
        unset item_domain_sans_hostpart
        oldifs=$IFS
        IFS=$'\n'
        let i=0
        #------------
        echo "--- Weighting Values" >> $emailmessage
        echo >> $emailmessage
        for value in `cat $ipsortedfile | uniq -c`
        do
                let working_ip_count=`echo $value | gawk '{ print $1 }'`
                let working_ip_weight=0
                if [ $working_ip_count -gt $ip_heavy_rate ]; then
                        let working_ip_weight=3
                else 
                        if [ $working_ip_count -gt $ip_midweight_rate ]; then
                                let working_ip_weight=2
                        else
                                if [ $working_ip_count -gt $ip_light_rate ]; then
                                        let working_ip_weight=1
                                fi
                        fi
                fi
                if [ $working_ip_weight -gt 0 ]; then
                        ip_count[$i]=$working_ip_count
                        ip_addr[$i]=`echo $value | gawk '{ print $2 }'`
                        ip_weight[$i]=$working_ip_weight
                        let i=$i+1
                fi
        done
        #------------
        value=""
        previous_domain=`head -n 1 $domainsortedfile | gawk '{ print $1 }'`
        let working_domain_weight=0
        let working_domain_count=0
        let i=0
        let y=0
        let total_weighted_ips=${#ip_count[@]}
        let new_domain_flag=0
        let prev_domain_hit_flag=0
        #------------
        for value in `cat $domainsortedfile | uniq -c`
        do
                let working_domain_per_ip_count=`echo $value | gawk '{ print $1 }'`
                working_domain=`echo $value | gawk '{ print $2 }'`
                working_ip=`echo $value | gawk '{ print $3 }'`
                for (( z = 0 ; z < total_weighted_ips ; z++ )); do
                        if [ "$working_ip" = "${ip_addr[$z]}" ] ; then
                                if [ "$working_domain" != "$previous_domain" ]; then
                                        previous_domain=$working_domain
                                        let new_domain_flag=1
                                        let working_domain_count=$working_domain_per_ip_count
                                        increase_pointer
                                        check_weight
                                else
                                        let working_domain_count=$working_domain_count+$working_domain_per_ip_count
                                        let new_domain_flag=0
                                        increase_pointer
                                        check_weight
                                fi
                        fi
                done
        done
        #------------
        let i=0
        let y=0
        value=""
        IFS=$oldifs
        let domain_ctr=${#domain_count[@]}
        let ip_ctr=${#ip_to_domain_count[@]}
        #------------
        for (( i = 0 ; i < domain_ctr ; i++ )); do
                echo "Count     Weight    Domain" >> $emailmessage
                echo "------------------------------" >> $emailmessage
                printf "${domain_count[$i]}" >> $emailmessage
                let x=10-${#domain_count[$i]}
                spaceit $x
                printf "${domain_weight[$i]}" >> $emailmessage
                let trigger=${domain_weight[$i]}
                let x=10-${#domain_weight[$i]}
                spaceit $x
                printf "${domain_name[$i]}\n" >> $emailmessage
                printf " |\n" >> $emailmessage
                for (( y = 0 ; y < ip_ctr ; y++ )); do
                        if [ ${ip_to_domain_ptr[$y]} = $i ]; then
                                printf " |- " >> $emailmessage
                                printf "${ip_to_domain_count[$y]}" >> $emailmessage
                                let x=7-${#ip_to_domain_count[$y]}
                                spaceit $x
                                printf "hits from ${ip_to_domain_ip[$y]}" >> $emailmessage
                                let x=16-${#ip_to_domain_ip[$y]}
                                spaceit $x
                                printf "( IP Weight = ${ip_total_weight[$y]} )\n" >> $emailmessage
                                let trigger=$trigger+${ip_total_weight[$y]}
                        fi
                done
                echo "  ================================> Total Weight = $trigger" >> $emailmessage
                let trigger_weight=$block_trigger_value*3
                echo "  ==============================> Trigger Value is $trigger_weight" >> $emailmessage
                echo "" >> $emailmessage
                dblquote=$'\042'
                sglquote=$'\047'
                vertbar=$'\174'
                hexstring=''
                if [ $trigger -gt $trigger_weight ]; then
                        let domain_parts=`echo ${domain_name[$i]} | gawk -F. '{ print NF }'`
                        for (( y =1 ; y <= domain_parts ; y++ )); do
                                hexvaltemp=`echo ${domain_name[$i]} | gawk -F. -v yy=$y '{ print $yy }' | xxd -c 256 -g 0 | gawk '{ print $2 }'`
                                let hexlen=${#hexvaltemp}-2
                                let hexlen_string_part=$hexlen/2
                                hexpartone=`echo "obase=16;($hexlen_string_part)" | bc | tr '[:upper:]' '[:lower:]'`
                                if [ ${#hexpartone} = 1 ]; then
                                        hexpartone="0"$hexpartone
                                fi
                                hexparttwo=`echo ${hexvaltemp:0:($hexlen)} | gawk '{ print tolower($0) }'`
                                hexstring="${hexstring}${hexpartone}${hexparttwo}"
                        done
                        mitigation_cmd="-A ${iptables_chain} -p udp -m string --hex-string ${dblquote}${vertbar}${hexstring}${vertbar}${dblquote} --algo bm  --to 65535 -m comment --comment ${dblquote}DNS_ATTACK_MITIGATION: Drop DNS domain: ${domain_name[$i]} at ${current_epoch}${dblquote} -j DROP"
                        if [ $report_only_flag = 0 ]; then
                                if [ $mitigate_attack = 1 ]; then
                                        let mitigation_taken=1
                                        iptables_restore_file=$(mktemp)
                                        echo '*filter' >> $iptables_restore_file
                                        echo $mitigation_cmd >> $iptables_restore_file
                                        echo 'COMMIT' >> $iptables_restore_file
                                        iptables-restore -n $iptables_restore_file
                                        if [ $? != 0 ]; then
                                                echo "Mitigation Command Failed"
                                        else
                                                rm -f $iptables_restore_file
                                        fi
                                fi
                        fi
                        echo "**********************************************************************" >> $emailmessage
                        echo "***                                                                ***" >> $emailmessage
                        printf "***" >> $emailmessage
                        if [ $mitigation_taken = 1 ]; then
                                let z=70-6-18-${#domain_name[$i]}
                                let z=$z/2
                                spaceit $z
                                printf "${domain_name[$i]} has been blocked." >> $emailmessage
                                echo "${domain_name[$i]} has been blocked with a total weight of $trigger over $trigger_weight required." >> $summaryemail
                                x=70-6-18-${#domain_name[$i]}-$z
                                spaceit $x
                        else
                                let needs_review=1
                                let z=70-6-14-${#domain_name[$i]}
                                let z=$z/2
                                spaceit $z
                                printf "${domain_name[$i]} needs review." >> $emailmessage
                                echo "${domain_name[$i]} needs review  with a total weight of $trigger over $trigger_weight required." >> $summaryemail
                                x=70-6-14-${#domain_name[$i]}-$z
                                spaceit $x
                                
                        fi
                        printf "***\n" >> $emailmessage
                        echo "***                                                                ***" >> $emailmessage
                        echo "**********************************************************************" >> $emailmessage
                        echo >> $emailmessage
                        mitigation_cmd='iptables '${mitigation_cmd}
                        echo "Command used for blocking this domain:" >> $emailmessage
                        echo "--------------------------------------" >> $emailmessage
                        echo $mitigation_cmd >> $emailmessage
                fi
                echo >> $emailmessage
                echo >> $emailmessage
        done
        #------------
        rm -f $domainsortfile
        rm -f $domainsortedfile
        rm -f $ipsortfile
        rm -f $ipsortedfile
}

clean_up () {
        #------------
        workingfile=$(mktemp)
        workingfile2=$(mktemp)
        oldifs=$IFS
        IFS=$'\n'
        let rules_ctr=`iptables -nvL ${iptables_chain} --line-number | grep DNS_ATTACK_MITIGATION | wc -l`
        iptables -nvL ${iptables_chain} --line-number | grep DNS_ATTACK_MITIGATION | gawk '{ print $1 " " $25 " " $23 }' > $workingfile
        tac $workingfile > $workingfile2
        let block_removal_sec=$block_removal*3600
        let block_removal_trigger=$current_epoch-$block_removal_sec
        let iptables_clean_flag=0
        #------------
        echo "# Start #" > $emailmessage
        echo >> $emailmessage
        for value in `cat $workingfile2`
        do
                let rule_ptr=`echo $value | gawk '{ print $1 }'`
                let rule_stamp=`echo $value | gawk '{ print $2 }'`
                stamp_date=`date -d @$rule_stamp +"%Y-%m-%d %T %z"`
                rule_domain=`echo $value | gawk '{ print $3 }'`
                if [ $rule_stamp -lt $block_removal_trigger ]; then
                        echo "Rule Number: $rule_ptr || Time Stamp: of $stamp_date || Domain: $rule_domain - removed from iptables" >> $emailmessage
                        iptables -D ${iptables_chain} $rule_ptr
                        let iptables_clean_flag=1
                fi
        done
        echo >> $emailmessage
        #------------
        IFS=$oldifs
        rm -f $workingfile
        rm -f $workingfile2
}

current_epoch=`date +%s`
let time_trigger=$current_epoch-$max_time
emailmessage=$(mktemp)
summaryemail=$(mktemp)
let mitigation_taken=0
let needs_review=0

populatearrays
evaluate_hits

if [ $summarize_report = 1 ]; then
    tmpmessage=$emailmessage
    emailmessage=$summaryemail
    rm -f $tmpmessage
fi

if [ $mitigation_taken = 1 ]; then
        mailit $email_destination "$email_subject_mitigated"
else if [ $needs_review = 1 ]; then
                mailit $email_destination "$email_subject_report_only"
        else
                clean_up
                if [ $iptables_clean_flag -eq 1 ]; then
                    mailit $email_destination "$email_subject_rule_cleanup"
                fi
        fi
fi
rm -f $emailmessage
rm -f $summaryemail
exit 0
