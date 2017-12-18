#!/usr/bin/perl
# debhelper addon script for dh-ima
# written in 2017 by Paul Tagliamonte <paultag@debian.org>

use warnings;
use strict;
use Debian::Debhelper::Dh_Lib;

insert_after("dh_gencontrol", "dh_ima");

1
