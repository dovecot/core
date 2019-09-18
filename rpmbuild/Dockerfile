ARG image=centos:6.10
FROM ${image}

RUN yum --assumeyes update && \
    yum --assumeyes install pam-devel bzip2-devel libcap-devel \
       libtool mysql-devel quota-devel xz-devel tcp_wrappers-devel \
       gettext-devel libcurl-devel postgresql-devel sqlite-devel clucene-core-devel \
       expat-devel openldap-devel rpm-build redhat-rpm-config make gcc gcc-c++


WORKDIR /dovecot/rpmbuild

ENTRYPOINT ./entrypoint.sh
