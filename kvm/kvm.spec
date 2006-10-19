Name:           kvm
Version:        0.0
Release:        0
Summary:        Kernel Virtual Machine virtualization environment

Group:          System Environment/Kernel
License:        GPL
URL:            http://www.qumranet.com
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}

ExclusiveArch:  i386 x86_64

Requires:	qemu kvm-kmod
BuildRequires:  SDL-devel zlib-devel > compat-gcc-32

%description
The Kernel Virtual Machine provides a virtualization enviroment for processors
with hardware support for virtualization: Intel's VT and AMD's AMD-V.

%prep

%build

rm -rf %{buildroot}

%install

%define bindir /usr/bin
%define bin %{bindir}/kvm
%define initdir /etc/init.d
%define confdir /etc/kvm
%define utilsdir /etc/kvm/utils
mkdir -p %{buildroot}/%{bindir}
mkdir -p %{buildroot}/%{confdir}
mkdir -p %{buildroot}/%{initdir}
mkdir -p %{buildroot}/%{utilsdir}
cp %{objdir}/qemu/x86_64-softmmu/qemu-system-x86_64 %{buildroot}/%{bin}
cp %{objdir}/scripts/kvm %{buildroot}/%{initdir}/kvm
cp %{objdir}/scripts/qemu-ifup %{buildroot}/%{confdir}/qemu-ifup
cp %{objdir}/kvm %{buildroot}/%{utilsdir}/kvm

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
