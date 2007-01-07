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

BuildRequires:  SDL-devel zlib-devel alsa-lib-devel

%define _prebuilt %{?prebuilt:1}%{!?prebuilt:0}

%if !%{_prebuilt}
Source0: kvm.tar.gz
Source1: user.tar.gz
Source2: kernel.tar.gz
Source3: scripts.tar.gz
Source4: Makefile
%endif

%description
The Kernel Virtual Machine provides a virtualization enviroment for processors
with hardware support for virtualization: Intel's VT and AMD's AMD-V.

%prep

%if !%{_prebuilt}
%setup -T -b 0 -n qemu
%setup -T -b 1 -n user -D
%setup -T -b 2 -n kernel -D
%setup -T -b 3 -n scripts -D
cd ..
cp %{_sourcedir}/Makefile .
%endif

%build

rm -rf %{buildroot}

%if !%{_prebuilt}
cd ..
make -C user
(cd qemu; ./kvm-configure)
make -C qemu
%endif

%install

%if !%{_prebuilt}
cd ..
%else
cd %{objdir}
%endif

make DESTDIR=%{buildroot} install-rpm

%define bindir /usr/bin
%define bin %{bindir}/kvm
%define initdir /etc/init.d
%define confdir /etc/kvm
%define utilsdir /etc/kvm/utils

%post 
depmod %{kverrel}
/sbin/chkconfig --level 2345 kvm on
/sbin/chkconfig --level 16 kvm off
/usr/sbin/groupadd -fg 444 kvm

%postun

depmod %{kverrel}

%clean
%{__rm} -rf %{buildroot}

%files
/usr/bin/kvm
%{confdir}/qemu-ifup
%{initdir}/kvm  
%{utilsdir}/kvm
/etc/udev/rules.d/*kvm*.rules
%changelog
