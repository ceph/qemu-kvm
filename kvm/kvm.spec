Name:           kvm
Version:        0.0
Release:        0
Summary:        Kernel Virtual Machine virtualization environment

Group:          System Environment/Kernel
License:        GPL
URL:            http://www.qumranet.com
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}

ExclusiveArch:  i386 x86_64

Requires:	qemu kvm-kmod bridge-utils

%define fedora_release %(rpm -q --qf '%%{version}' fedora-release)

%if %{fedora_release} == 5
BuildRequires: compat-gcc-32
%else
BuildRequires: compat-gcc-34
%endif

BuildRequires:  SDL-devel zlib-devel

%description
The Kernel Virtual Machine provides a virtualization enviroment for processors
with hardware support for virtualization: Intel's VT and AMD's AMD-V.

%prep

%build

rm -rf %{buildroot}

%install

make -C %{objdir} DESTDIR=%{buildroot} install

%define bindir /usr/bin
%define bin %{bindir}/kvm
%define initdir /etc/init.d
%define confdir /etc/kvm
%define utilsdir /etc/kvm/utils

%post 
depmod %{kverrel}
/sbin/chkconfig --level 2345 kvm on
/sbin/chkconfig --level 16 kvm off

%postun

depmod %{kverrel}

%clean

%files
/usr/bin/kvm
%{confdir}/qemu-ifup
%{initdir}/kvm  
%{utilsdir}/kvm
%changelog
