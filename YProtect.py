#!/usr/bin/python

import os
import plistlib
import syslog
import time
import urllib
from platform import mac_ver

installed_flash_vers = None
installed_java_vers = None
site = None
flash_path = '/Library/Internet Plug-Ins/Flash Player.plugin/Contents/Info.plist'
java_path = '/Library/Internet Plug-Ins/JavaAppletPlugin.plugin/Contents/Info.plist'
xp_path = '/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.plist'
xpm_path = '/System/Library/CoreServices/CoreTypes.bundle/Contents/Resources/XProtect.meta.plist'

# map os versions to numbers used in XProtect URL
version_map = {'6': '1', '7': '2', '8': '3'}

# slice out the 6,7,or 8 from first tuple returned by mac_ver
os_vers = mac_ver()[0][3:4]

# assign URL with proper number to variable
plist_url = 'http://configuration.apple.com/configurations/macosx/xprotect/%s/clientConfiguration.plist' % version_map[os_vers]

# 'Create a file-like object...' - help(urlib.urlopen) and Python Library site
try:
    site = urllib.urlopen(plist_url)
except:
    syslog.syslog(syslog.LOG_CRIT, 'Could not open plist_url!')

if site:
    # read site into a new string object called
    alldata = site.read()

    # assign lowest index of "<?xml" to start
    start = alldata.find("<?xml")

    # returns the root object of the slice of alldata from index of "<?xml" to end
    remote_plist = plistlib.readPlistFromString(alldata[start:])

    # assign the values of the specified keys to seperate objects
    remote_data = remote_plist['data']
    remote_meta = remote_plist['meta']
    remote_blacklist = remote_meta['PlugInBlacklist']['10']
else:
    syslog.syslog(syslog.LOG_CRIT, 'Site not set. Check for plist_url error.')
    os._exit(1)

# read in the local files for comparison
local_data = plistlib.readPlist(xp_path)
local_meta = plistlib.readPlist(xpm_path)
local_blacklist = local_meta['PlugInBlacklist']['10']

# get local Java and Flash versions to set versions to match in meta
try:
    installed_flash_plist = plistlib.readPlist(flash_path)
    installed_flash_vers = installed_flash_plist['CFBundleVersion']
except:
     syslog.syslog(syslog.LOG_ALERT, 'There was a problem getting the installed Flash version. Maybe it is not installed?')

try:
    installed_java_plist = plistlib.readPlist(java_path)
    installed_java_vers = installed_java_plist['CFBundleVersion']
except:
     syslog.syslog(syslog.LOG_ALERT, 'There was a problem getting the installed Java version. Maybe it is not installed?')


# Check if remote_data and local_data are not the same.
# If they are not then we will write a new one...assuming 
# for the time being that Apple only puts real malware
# in there then we can trust it. *crosses fingers*
if remote_data != local_data:
    plist_lib.writePlist(remote_data, xp_path)
    os.chown(xp_path, 0, 0)

# Check if len(remote_meta) + 1 == len(local_meta) this means Apple
# did not add any additional software to the checks, the +1 is for the 
# lack of 'LastModification' key in remote_meta
if len(remote_meta) + 1 != len(local_meta):
    syslog.syslog(syslog.LOG_ALERT, 'Apple may have changed the software in the meta list...better check it')
# Check the len() of the plugin blacklist just to be sure Apple didn't add anything here either
elif len(remote_blacklist) != len(local_blacklist):
     syslog.syslog(syslog.LOG_ALERT, 'Apple may have changed the software in PlugInBlacklist...better check it')
else:
    new_local_meta = local_meta
    # make a new XProtect.meta.plist using installed version numbers or the number from Apple if installed_vers
    # cannot be found
    if installed_flash_vers:
        local_blacklist['com.macromedia.Flash Player.plugin']['MinimumPlugInBundleVersion'] = installed_flash_vers
    else:
        local_blacklist['com.macromedia.Flash Player.plugin']['MinimumPlugInBundleVersion'] = remote_blacklist['com.macromedia.Flash Player.plugin']['MinimumPlugInBundleVersion']

    if installed_java_vers:
        local_blacklist['com.oracle.java.JavaAppletPlugin']['MinimumPlugInBundleVersion'] = installed_java_vers
    else:
        local_blacklist['com.oracle.java.JavaAppletPlugin']['MinimumPlugInBundleVersion'] = remote_blacklist['com.oracle.java.JavaAppletPlugin']['MinimumPlugInBundleVersion']

    new_local_meta['PlugInBlacklist']['10'] = local_blacklist    
    # set the LastModification to the current time in the same format that Apple uses
    new_local_meta['LastModification'] = time.strftime('%a, %d %b %Y %H:%M:%S GMT', time.gmtime())
    # I can't find where JavaWebComponentVersion can be checked
    # The closest I got was CFBundleGetInfoString in /System/Library/Java/JavaVirtualMachines/1.6.0.jdk/Contents/Info.plist
    # but on my machine it is 'Java for Mac OS X (1.6.0_37-b06-434)' not *435 and I have the latest Java installed
    # so I dunno. I did all sorts of find -exec greps to try and weed it out...*shrug* Just going
    # to do the Neagle thing and delete it for now.
    del new_local_meta['JavaWebComponentVersionMinimum']
    plistlib.writePlist(new_local_meta, xpm_path)
    os.chown(xpm_path, 0, 0)
