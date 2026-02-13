%global debug_package %{nil}

# Header Section
Name:           spydar
Version:        SPYDARVERSION
Release:        1%{?dist}
Summary:        A program to measure dns caches for the presence of specific domain names.
License:        TODO
URL:            https://spydar.org/
Source0:        %{name}-%{version}.tar.gz
#BuildRequires:  gcc make 
Requires:       glibc

%description
A program to measure dns caches for the presence of specific domain names.

# Body Section (Scripts)

%prep
# Unpack the source tarball
%setup -q

%build
# Compile the source (assuming a standard Makefile setup)
make 
#%{?_smp_mflags}

%install
# Create destination directories in the build root
install -d %{buildroot}/usr/bin
#install -d %{buildroot}/etc/%{name}

# Copy the compiled binary and config file to the build root
install -m 0755 spydar/spydar.linux %{buildroot}/usr/bin/spydar.linux

%files
# List all files to be included in the RPM
/usr/bin/spydar.linux

%changelog
* Thu Jan 08 2026 Jane Doe <jane.doe@example.com> - 1.0.0-1
- Initial release of spydar

