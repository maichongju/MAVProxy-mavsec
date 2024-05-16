This is a fork of the MAVProxy project. The original readme file can be found at the bottom of this file. 

This project modify the MAVLink protocol to allow encrypted communication between the drone and the ground station, we call the newly modified protocol `MAVSec`.

A `crypto.xml` message defination included the newly added encryption message. However using `mavgen` with that xml file will not give the up to date `MAVSec` implementation. The up to data implementation can be found in the `pymavlink.dialects.v20.ardupilotmega` module.

Noted that the current implementation of `MAVSec` only support `MAVLink 2.0` protocol. 



## Original README

![GitHub Actions](https://github.com/ardupilot/MAVProxy/actions/workflows/windows_build.yml/badge.svg)

MAVProxy

This is a MAVLink ground station written in python. 

Please see https://ardupilot.org/mavproxy/index.html for more information

This ground station was developed as part of the CanberraUAV OBC team
entry

License
-------

MAVProxy is released under the GNU General Public License v3 or later


Maintainers
-----------

The best way to discuss MAVProxy with the maintainers is to join the
mavproxy channel on ArduPilot discord at https://ardupilot.org/discord

Lead Developers: Andrew Tridgell and Peter Barker

Windows Maintainer: Stephen Dade

MacOS Maintainer: Rhys Mainwaring
