
chmod 755 /home/opsgenie/oec/nagiosxi/send2opsgenie

if id -u nagios >/dev/null 2>&1; then
        usermod -a -G opsgenie nagios
else
        echo "WARNING : nagios user does not exist. Please don't forget to add your nagios user to opsgenie group!"
fi