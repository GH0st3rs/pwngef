#!/bin/sh
#
# This script is used for development only!
# it will cleanup the repository and nothing else
#
ROOTDIR=`dirname $0`
echo 'Deleting pyc files'
echo find $ROOTDIR -iname '*.pyc' -delete
find $ROOTDIR -iname '*.pyc' -delete
echo 'Deleting logs'
echo find $ROOTDIR -iname '*.log' -delete
find $ROOTDIR -iname '*.log' -delete
echo 'Deleting __pycache__'
echo find $ROOTDIR -name '__pycache__' -delete
find $ROOTDIR -name '__pycache__' -exec rm -rf {} \;
