
chmod 755 /usr/bin/nagios2opsgenie


if id -u nagios >/dev/null 2>&1; then
        usermod -a -G opsgenie nagios
else
        echo "WARNING : nagios user does not exist. Please don't forget to add your nagios user to opsgenie group!"
fi

cp /etc/opsgenie/opsgenie.cfg  /opt/monitor/etc/mconf
cp /etc/opsgenie/opsgenie.cfg  /opt/monitor/etc
chown monitor:apache /etc/opsgenie/opsgenie.cfg
chown monitor:apache /opt/monitor/etc/opsgenie.cfg
chown monitor:apache /opt/monitor/etc/mconf/opsgenie.cfg
chmod 664 /etc/opsgenie/opsgenie.cfg
chmod 664 /opt/monitor/etc/opsgenie.cfg
chmod 664 /opt/monitor/etc/mconf/opsgenie.cfg