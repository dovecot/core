#!/bin/sh
VERSION=$1
DIR_FILES=$2

sudo apt update
sudo apt-get install -y zip unzip

cd $DIR_FILES/Pack/src/ && zip -r $DIR_FILES/Packages/r7mdaserver_${VERSION}.zip *
md5sum $DIR_FILES/Packages/r7mdaserver_${VERSION}.zip >> $DIR_FILES/Packages/md5.txt