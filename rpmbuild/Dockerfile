ARG image=centos:6.10
FROM ${image}

# make sure we have rpmbuild and yum-builddep
RUN yum --assumeyes update && \
    yum --assumeyes install rpm-build yum-utils --enablerepo=extras

# install dependencies from .spec file
COPY SOURCES/dovecot.spec /tmp/dovecot.spec
RUN  yum-builddep --assumeyes /tmp/dovecot.spec

WORKDIR /dovecot/rpmbuild

ENTRYPOINT ./entrypoint.sh
