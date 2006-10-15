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
BuildRequires:  SDL-devel zlib-devel compat-gcc-32

%description
The Kernel Virtual Machine provides a virtualization enviroment for processors
with hardware support for virtualization: Intel's VT and AMD's AMD-V.

%prep

%build

rm -rf %{buildroot}

%install

%define bindir /usr/bin
%define bin %{bindir}/kvm
mkdir -p %{buildroot}/%{bindir}
cp %{objdir}/qemu/x86_64-softmmu/qemu-system-x86_64 %{buildroot}/%{bin}

%post 

depmod %{kverrel}

%postun

depmod %{kverrel}

%clean

%files
/usr/bin/kvm

%changelog
