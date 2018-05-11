#!/bin/sh
##########################################################################################
#
# DISTRIBUTION STATEMENT A. Approved for public release: distribution unlimited.
#
# This material is based upon work supported by the Assistant Secretary of Defense for 
# Research and Engineering under Air Force Contract No. FA8721-05-C-0002 and/or 
# FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in 
# this material are those of the author(s) and do not necessarily reflect the views of the 
# Assistant Secretary of Defense for Research and Engineering.
#
# Copyright 2017 Massachusetts Institute of Technology.
#
# The software/firmware is provided to you on an As-Is basis
#
# Delivered to the US Government with Unlimited Rights, as defined in DFARS Part 
# 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government 
# rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed 
# above. Use of this work other than as specifically authorized by the U.S. Government may 
# violate any copyrights that exist in this work.
#
##########################################################################################


# Start web server
#nginx


# Pause for demo effect 
#sleep 0.25m


# Set up new protected space on web server
#cryptsetup luksFormat /var/www/html/payload.enc keyfile.txt
#cryptsetup luksOpen /var/www/html/payload.enc encdrive --key-file keyfile.txt
#mkfs.ext4 -j /dev/mapper/encdrive


# Decrypt and mount protected web server data
mkdir -p /var/www/html/payload/
cryptsetup luksOpen /var/www/html/payload.enc encdrive --key-file keyfile.txt
mount /dev/mapper/encdrive /var/www/html/payload/


# Unmount encrypted space 
#umount /var/www/html/payload
#cryptsetup luksClose encdrive
#nginx -s quit