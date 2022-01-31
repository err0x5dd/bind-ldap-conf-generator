import ldap
import sys
import os
import glob

import config

# flags
FLAG_DEBUG = False
#FLAG_DEBUG = True
FLAG_IGNORE_PRIMARY = True


# connect to ldap server
try:
    conn = ldap.initialize(config.ldapsrv)
except:
    sys.exit("Can't connect to ldap server: '" + config.ldapsrv + "'")

# bind to ldap server
try:
    msgid = conn.simple_bind(config.binduser, config.bindpw)
except:
    sys.exit("Can't bind to ldap server using dn: '" + config.binduser + "'")

ret = conn.result(msgid)




oldsoaserials = {}

os.chdir(config.zonedir)
for file in glob.glob("*.zone"):
    with open(config.zonedir + "/" + file, "r") as f:
        flines = f.readlines()
        for line in flines:
            if "IN SOA" in line:
                oldsoaserials.update({file[:-5]: line.split()[6]})

if FLAG_DEBUG:
    print("oldsoaserials: " + str(oldsoaserials))



newsoaserials = {}

## search for soa entries / zones and return zone name and serial
try:
    msgid = conn.search(config.soabase, config.soascope, config.soafilter, ["cn", config.soazone, config.soaserial])
except:
    sys.exit("Error while searching for SOA entries")

ret = conn.result(msgid)
if ret[0] != 101:
    sys.exit("Search request didn't return search result")

for i in ret[1]:
    zone = i[1].get(config.soazone)[0].decode("utf-8")
    if zone[-1] == ".":
        zone = zone[:-1]
    newsoaserials.update({zone: i[1].get(config.soaserial)[0].decode("utf-8")})

if FLAG_DEBUG:
    print("newsoaserials: " + str(newsoaserials))
    print()


zoneupdates = {}
zonelist = {}
zoneindex = 0

for zone in newsoaserials:
    if zone in oldsoaserials:
        if newsoaserials.get(zone) > oldsoaserials.get(zone):
            zoneupdates.update({zone: "update"})
            zonelist.update({zone: zoneindex})
            zoneindex = zoneindex + 1
        else:
            zoneupdates.update({zone: "keep"})
            zonelist.update({zone: zoneindex})
            zoneindex = zoneindex + 1
    else:
        zoneupdates.update({zone: "add"})
        zonelist.update({zone: zoneindex})
        zoneindex = zoneindex + 1

for zone in oldsoaserials:
    if zone not in newsoaserials:
        zoneupdates.update({zone: "remove"})
        

if FLAG_DEBUG:
    print(zoneupdates)
    print()



## remove old files

for file in os.scandir(config.zonedir):
    os.remove(file.path)

#### Create and build zone

#zonelist = {"test.": 0, "lab": 1, "home.err0x5dd.de": 2}

filename = []
zonetext = []

#-------- loop

for zone in zonelist:
    zoneindex = zonelist[zone]
    
    if FLAG_DEBUG:
        print("Zone: " + zone)
    
    #zoneindex = 0
    
    dntext = ""
    soatext = ""
    nstext = "; NS entries\n"
    atext = "; A entries\n"
    aaaatext = "; AAAA entries\n"
    cnametext = "; CNAME entries\n"
    txttext = "; TXT entries\n"
    mxtext = "; MX entries\n"
    
    # ldap search for only entries within current zone
    
    
    nsrecords = []
    arecords = []
    aaaarecords = []
    cnamerecords = []
    txtrecords = []
    mxrecords = []
    
    
    
    # request soa entry for current zone
    try:
        msgid = conn.search(config.soabase, config.soascope, "(&(" + config.soazone + "=" + zone + ")" + config.soafilter + ")", [config.soazone, config.soaprimary, config.soamail, config.soaserial, config.soarefresh, config.soaretry, config.soaexpire, config.soaminttl])
    except:
        sys.exit("Error while searching for SOA entry")
    
    ret = conn.result(msgid)
    if ret[0] != 101:
        sys.exit("Search request didn't return search result")
    
    if len(ret[1]) == 0:
        sys.exit("No SOA entry for " + zone + " found")
    
    # DN extraction for comment
    dntext = "; SOA Entry DN: " + ret[1][0][0] + "\n"
    
    ret = ret[1][0][1]
    
    
    # SOA extraction
    soazone = ret.get(config.soazone)[0].decode("utf-8")
    if soazone[-1] != ".":
        soazone = soazone + "."
    
    soaprimary = ret.get(config.soaprimary)[0].decode("utf-8")
    if soaprimary[-1] != ".":
        soaprimary = soaprimary + "."
    
    soamail = ret.get(config.soamail)[0].decode("utf-8")
    if soamail[-1] != ".":
        soamail = soamail + "."
    
    soaserial = ret.get(config.soaserial)[0].decode("utf-8")
    soarefresh = ret.get(config.soarefresh)[0].decode("utf-8")
    soaretry = ret.get(config.soaretry)[0].decode("utf-8")
    soaexpire = ret.get(config.soaexpire)[0].decode("utf-8")
    soaminttl = ret.get(config.soaminttl)[0].decode("utf-8")
    
    soatext =  soazone + " IN SOA " + soaprimary + " " + soamail + " ( " + soaserial + " " + soarefresh + " " + soaretry + " " + soaexpire + " " + soaminttl + " )\n"
    
    
    
    # request all entries about the current zone
    try:
        msgid = conn.search(config.entrybase, config.entryscope, "(&(" + config.entryzone + "=" + zone + ")" + config.entryfilter + ")", [config.entryzone, config.entryhost, config.entrya, config.entryaaaa, config.entrycname, config.entrytxt, config.entryns, config.entrymx])
    except:
        sys.exit("Error while searching for zone entries")
    
    ret = conn.result(msgid)
    if ret[0] != 101:
        sys.exit("Search request didn't return search result")
    
    if len(ret[1]) == 0:
        if FLAG_DEBUG:
            print("No entries for zone " + zone)
    
    for entry in ret[1]:
        #print("Entry: " + str(entry))
        host = entry[1].get(config.entryhost)[0].decode("utf-8")
        for recordtype in entry[1]:
            #print("Type: " + recordtype)
            if recordtype == config.entryzone or recordtype == config.entryhost:
                continue
            for i in entry[1].get(recordtype):
                #print("i: " + i.decode("utf-8"))
                if recordtype == config.entryns:
                    #if host[-1] != ".":
                    #    host = host + "."
                    #print("NS: " + str((host, i.decode("utf-8"))))
                    nsrecords.append((host, i.decode("utf-8")))
                elif recordtype == config.entrya:
                    #print("A: " + str((host, i.decode("utf-8"))))
                    arecords.append((host, i.decode("utf-8")))
                elif recordtype == config.entryaaaa:
                    aaaatext = aaaatext + "; not yet implemented\n"
                elif recordtype == config.entrycname:
                    #print("CNAME: " + str((host, i.decode("utf-8"))))
                    cnamerecords.append((host, i.decode("utf-8")))
                elif recordtype == config.entrytxt:
                    txttext = txttext + "; not yet implemented\n"
                elif recordtype == config.entrymx:
                    mxtext = mxtext + "; not yet implemented\n"
    
    
    
    for record in nsrecords:
        nstext =  nstext + record[0] + " IN NS " + record[1] + "\n"
    
    for record in arecords:
        atext = atext + record[0] + " IN A " + record[1] + "\n"
    
    for record in cnamerecords:
        cnametext = cnametext + record[0] + " IN CNAME " + record[1] + "\n"
    
    
    
    zonetext.insert(zoneindex, "$TTL 7200\n\n" + dntext + "\n" + soatext + "\n\n" + nstext + "\n\n" + atext + "\n\n" + aaaatext + "\n\n" + cnametext + "\n\n" + txttext + "\n\n" + mxtext + "\n\n")
    
    if FLAG_DEBUG:
        print(zonetext[zoneindex])
    
    with open(config.zonedir + "/" + zone + ".zone", "w") as f:
        f.write(zonetext[zoneindex])
    
    zoneconf = "zone \"" + zone + "\" { type master; file \"" + config.zonedir + "/" + zone + ".zone\"; };\n"
    with open(config.zoneconf, "a") as f:
        f.write(zoneconf)
    # zone "home.err0x5dd.de" { type master; file "/etc/named/home.err0x5dd.de.zone"; };

# reload dns config
os.system("rc-service named reload")
