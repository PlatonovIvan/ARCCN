import sys
f=open(r"Switch1_300New", "w")
sys.stdout=f
string="permit icmp 192.168.20.0 0.0.0.255"
addr=[7,0,0,0]
port=1024
for i in xrange(300):
    print "%s %s %s.%s.%s.%s 0.0.0.0 any" %(string, port, addr[0], addr[1], addr[2], addr[3])
    if (addr[3]<255):
        addr[3]+=1
    else:
        addr[2]+=1
        addr[3]=0
    port+=1
print "permit tcp 0.0.0.0 255.255.255.255 any 0.0.0.0 255.255.255.255 any"
print "permit icmp 0.0.0.0 255.255.255.255 any 0.0.0.0 255.255.255.255 any"
f.close()
