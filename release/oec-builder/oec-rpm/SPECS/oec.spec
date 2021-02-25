Name: %INTEGRATION%
Version: %VERSION%
Summary: OEC (%INTEGRATION%) for Connecting On-Premise Monitoring and ITSM Tools
Release: 1
License: Apache-2.0
URL: https://www.opsgenie.com/
Group: System
Packager: Opsgenie
BuildRoot: .

%description
Opsgenie Edge Connector (OEC) is designed to resolve challenges faced in the integration of internal and external systems.

%prep
echo "BUILDROOT = $RPM_BUILD_ROOT"
mkdir -p $RPM_BUILD_ROOT/usr/local/bin/
mkdir -p $RPM_BUILD_ROOT/etc/systemd/system/
mkdir -p $RPM_BUILD_ROOT/home/opsgenie/oec/
cp $GITHUB_WORKSPACE/.release/oec-rpm/OpsgenieEdgeConnector $RPM_BUILD_ROOT/usr/local/bin/
cp $GITHUB_WORKSPACE/.release/oec-rpm/oec.service $RPM_BUILD_ROOT/etc/systemd/system/
cp -R $GITHUB_WORKSPACE/.release/oec-rpm/oec-scripts/. $RPM_BUILD_ROOT/home/opsgenie/oec/

%pre
if [ ! -d "/var/log/opsgenie" ]; then
    mkdir /var/log/opsgenie
fi

if [ ! -d "/home/opsgenie" ]; then
    mkdir /home/opsgenie
fi

if [  -z $(getent passwd opsgenie) ]; then
    groupadd opsgenie -r
    useradd -g opsgenie opsgenie -r -d /home/opsgenie
fi

%post
chown -R opsgenie:opsgenie /home/opsgenie
chown -R opsgenie:opsgenie /var/log/opsgenie

chmod +x /etc/systemd/system/oec.service
chmod +x /usr/local/bin/OpsgenieEdgeConnector
systemctl daemon-reload
systemctl enable oec

%postun
systemctl daemon-reload

%files
/usr/local/bin/OpsgenieEdgeConnector
/etc/systemd/system/oec.service
/home/opsgenie/oec/

%changelog
* Mon Jan 28 2019  Emel Komurcu
- 1.0 r1 First release