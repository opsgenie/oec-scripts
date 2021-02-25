Name: %INTEGRATION%-rhel6
Version: %VERSION%
Summary: OEC (%INTEGRATION%) for Connecting On-Premise Monitoring and ITSM Tools
Release: 1
License: Apache-2.0
URL: https://www.opsgenie.com/
Group: System
Packager: Opsgenie
BuildRoot: ~/rpmbuild/

%description
Opsgenie Edge Connector (OEC) is designed to resolve challenges faced in the integration of internal and external systems.

%prep
echo "BUILDROOT = $RPM_BUILD_ROOT"
mkdir -p $RPM_BUILD_ROOT/usr/local/bin/
mkdir -p $RPM_BUILD_ROOT/home/opsgenie/oec/
cp $GITHUB_WORKSPACE/.release/oec-rpm/OpsgenieEdgeConnector $RPM_BUILD_ROOT/usr/local/bin/
cp -R  $GITHUB_WORKSPACE/.release/oec-rpm/oec-scripts/. $RPM_BUILD_ROOT/home/opsgenie/oec/

mkdir -p $RPM_BUILD_ROOT/etc/init.d/
cp $GITHUB_WORKSPACE/.release/oec-rpm/rhel6-service/oec $RPM_BUILD_ROOT/etc/init.d/

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

chmod +x /usr/local/bin/OpsgenieEdgeConnector

chmod +x /etc/init.d/oec
service oec start

%postun
service oec stop
rm /etc/init.d/oec

%files
/usr/local/bin/OpsgenieEdgeConnector
/etc/init.d/oec
/home/opsgenie/oec/

%changelog
