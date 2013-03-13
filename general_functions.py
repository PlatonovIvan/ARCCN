def Tree_Print(rule_tree):
    for i in rule_tree:
        for j in i:
            for k in j:
                for l in k:
                    for m in l:
                        for n in m:
                            #print "protocol=", n.protocol
                            #print "src_ip=", n.src_addr
                            #print "src_port=", n.src_port
                            #print "dst_addr=", n.dst_addr
                            #print "dst_port=", n.dst_port
                            #print "number=", n.number+1
                            #print "state=", n.state
                            print n.action, n.src_addr, n.src_mask, "to", n.dst_addr, n.dst_mask




def List_Print(rule_list):
    for i in rule_list:
        print i.number, i.action, i.src_addr, i.src_port, i.dst_addr, i.dst_port

def tree_to_list(rule_tree, rule_list):
    for a in xrange(len(rule_tree)):# perebor po proto
        for b in xrange(len(rule_tree[a])): # perebor po src_addr 
            for c in xrange(len(rule_tree[a][b])): # perebor po src_port
                for d in xrange(len(rule_tree[a][b][c])): # perebor po dst_addr
                    for e in xrange(len(rule_tree[a][b][c][d])): # perebor po dst_port
                        for f in xrange(len(rule_tree[a][b][c][d][e])):# perebor po number
                            rule_list.append(rule_tree[a][b][c][d][e][f])


def Correct_Order(rule_tree):
    """
    returns the number of rules
    """
    num=0
    for a in xrange(len(rule_tree)):# perebor po proto
        for b in xrange(len(rule_tree[a])): # perebor po src_addr 
            for c in xrange(len(rule_tree[a][b])): # perebor po src_port
                for d in xrange(len(rule_tree[a][b][c])): # perebor po dst_addr
                    for e in xrange(len(rule_tree[a][b][c][d])): # perebor po dst_port
                        for f in xrange(len(rule_tree[a][b][c][d][e])): # perebor po number
                            rule_tree[a][b][c][d][e][f].number=num
                            num+=1
    return num

def convert_mask(mask):
    """
    converts mask from list [255, 255, 255, 0] to int /24
    """

    num=0
    temp=""
    flag=True
    for i in xrange (0,4):
        temp+=(str(bin(mask[i]))[2:]) # every binary number in python starts with 0b
    for i in xrange(len(temp)):
        if (temp[i]=="1"):
            if (flag):
                num+=1
            else:
                num=-1
                break
        else:
            flag=False
    return num


def addr_belongs_to_subnet (subnet, mask, addr):

    def normalize(temp_addr):
        temp=""
        for i in (xrange(len(temp_addr)-2, 8)):
            temp+="0"
        return temp+temp_addr[2:]
       
    num=0
    temp=""
    if (type(mask)==list):
        num=convert_mask(mask)
        if (num==-1):
            print "Bad mask"
            return False
    else:
        num=mask
    temp_subnet=""
    temp_subnet=normalize(str(bin(subnet[0])))+\
                normalize(str(bin(subnet[1])))+\
                normalize(str(bin(subnet[2])))+\
                normalize(str(bin(subnet[3])))
        
    temp_addr=normalize(str(bin(addr[0])))+\
              normalize(str(bin(addr[1])))+\
              normalize(str(bin(addr[2])))+\
              normalize(str(bin(addr[3])))

    #print "+++++++++++++++++++++++++++++++++++++"
    #print "subnet=", subnet, temp_subnet
    #print "mask=", mask
    #print "addr=", addr, temp_addr
    
    for i in xrange(0, num):
      if (temp_addr[i]!=temp_subnet[i]):
        return False
    return True



def addr_subset(addr_1, addr_2, mask_2): #addr1 is subset of addr2
    """
    returns 1 if addr_1 is subset of addr_2
            2 if addr_1==addr_2
            0 else
    """
    #print "addr_1=", addr_1
    #print "subnet=", addr_2, mask_2
    if (addr_1==addr_2):
        #print "True"
        return 2
    elif (addr_belongs_to_subnet(addr_2, mask_2, addr_1)):
        #print "True"
        return 1
    else:
        #print "False"
        return -1


            
def number_of_equal_bytes(addr_1, addr_2): #addr1 is subset of addr2
    """
    returns kol of equal bytes if addr_1 is subset of addr_2
    """
    x=bin(addr_1[0]*256*256*256+addr_1[1]*256*256+addr_1[2]*256+addr_1[3])
    y=bin(addr_2[0]*256*256*256+addr_2[1]*256*256+addr_2[2]*256+addr_2[3])
    if (len(x)!=len(y)):
        return 0
    number=0
    for i in xrange(len (x)):
        if (x[i]==y[i]):
            number+=1
        else:
            return number 
            
def src_port_subset(rule1, rule2): #rule1 is subset of rule2
    """
    returns 1 if rule1 is subset of rule2
            2 if rule1==rule2
            3 if Needs to be split ??????
            0 else
    """
    min_port_1=0
    min_port_2=0
    max_port_1=0
    max_port_2=0
    if (rule1.src_port_operator=="")&(rule2.src_port_operator==""):
        if (rule1.src_port==rule2.src_port):
            return 2
        else:
            return 0
    if (rule1.src_port_operator!=""):
        if (rule1.src_port_operator=="any"):
            min_port_1=0
            max_port_1=65535
        elif (rule1.src_port_operator=="eq"):
            min_port_1=rule1.src_port
            max_port_1=rule1.src_port
        elif (rule1.src_port_operator=="gt"):
            min_port_1=rule1.src_port
            max_port_1=65535
        elif (rule1.src_port_operator=="host"):
            min_port_1=rule1.src_port
            max_port_1=rule1.src_port
        elif (rule1.src_port_operator=="lt"):
            min_port_1=0
            max_port_1=rule1.src_port
        elif (rule1.src_port_operator=="neq"):
            pass
        elif (rule1.src_port_operator=="range"):
            min_port_1=rule1.src_port[0]
            max_port_1=rule1.src_port[1]
    else:
        min_port_1=rule1.src_port
        max_port_1=rule1.src_port
        

    if (rule2.src_port_operator!=""):
        if (rule2.src_port_operator=="any"):
            min_port_2=0
            max_port_2=65535
        elif (rule2.src_port_operator=="eq"):
            min_port_2=rule2.src_port
            max_port_2=rule1.src_port
        elif (rule2.src_port_operator=="gt"):
            min_port_2=rule2.src_port
            max_port_2=65535
        elif (rule2.src_port_operator=="host"):
            min_port_2=rule2.src_port
            max_port_2=rule1.src_port
        elif (rule2.src_port_operator=="lt"):
            min_port_2=0
            max_port_2=rule2.src_port
        elif (rule2.src_port_operator=="neq"):
            pass
        elif (rule2.src_port_operator=="range"):
            min_port_2=rule2.src_port[0]
            max_port_2=rule2.src_port[1]
    else:
        min_port_2=rule2.src_port
        max_port_2=rule2.src_port
    
    if (min_port_1==min_port_2)&(max_port_1==max_port_2):
        return 2
    if (min_port_2<=min_port_1):
        if(max_port_1<=max_port_2):
            return 1
        else:
            return 3
    return 0
    

def dst_port_subset(rule1, rule2):
    """
    returns 1 if rule1 is subset of rule2
            2 if rule1==rule2
            0 else
    """
    min_port_1=0
    min_port_2=0
    max_port_1=0
    max_port_2=0
    if (rule1.dst_port_operator=="")&(rule2.dst_port_operator==""):
        if (rule1.dst_port==rule2.dst_port):
            return 2
        else:
            return 0
    if (rule1.dst_port_operator!=""):
        if (rule1.dst_port_operator=="any"):
            min_port_1=0
            max_port_1=65535
        elif (rule1.dst_port_operator=="eq"):
            min_port_1=rule1.dst_port
            max_port_1=rule1.dst_port
        elif (rule1.dst_port_operator=="gt"):
            min_port_1=rule1.dst_port
            max_port_1=65535
        elif (rule1.dst_port_operator=="host"):
            min_port_1=rule1.dst_port
            max_port_1=rule1.dst_port
        elif (rule1.dst_port_operator=="lt"):
            min_port_1=0
            max_port_1=rule1.dst_port
        elif (rule1.dst_port_operator=="neq"):
            pass
        elif (rule1.dst_port_operator=="range"):
            min_port_1=rule1.dst_port[0]
            max_port_1=rule1.dst_port[1]
    else:
        min_port_1=rule1.dst_port
        max_port_1=rule1.dst_port
        

    if (rule2.dst_port_operator!=""):
        if (rule2.dst_port_operator=="any"):
            min_port_2=0
            max_port_2=65535
        elif (rule2.dst_port_operator=="eq"):
            min_port_2=rule2.dst_port
            max_port_2=rule1.dst_port
        elif (rule2.dst_port_operator=="gt"):
            min_port_2=rule2.dst_port
            max_port_2=65535
        elif (rule2.dst_port_operator=="host"):
            min_port_2=rule2.dst_port
            max_port_2=rule1.dst_port
        elif (rule2.dst_port_operator=="lt"):
            min_port_2=0
            max_port_2=rule2.dst_port
        elif (rule2.dst_port_operator=="neq"):
            pass
        elif (rule2.dst_port_operator=="range"):
            min_port_2=rule2.dst_port[0]
            max_port_2=rule2.dst_port[1]
    else:
        min_port_2=rule2.dst_port
        max_port_2=rule2.dst_port

    

    if (min_port_1==min_port_2)&(max_port_1==max_port_2):
        return 2
    if (min_port_2<=min_port_1):
        if(max_port_1<=max_port_2):
            return 1
        else:
            return 3
    return 0

def addr_to_list(addr):
    """
    converts addr from "10.0.0.1/24 to [10,0,0,0]"
    """
    if (type(addr)!=str):
        return addr
    temp=addr.split("/")
    ip_addr=temp[0].split(".")
    for i in xrange(len(ip_addr)):
      ip_addr[i]=int(ip_addr[i])
    return ip_addr

def mask_to_list(addr):
    """
    converts mask from "10.0.0.1/24" to [255, 255, 255, 0]
    """
    temp=addr.split("/")
    num=int(temp[1])
    mask_list=[]
    for i in xrange(0,4):
      temp=0
      for j in xrange(7, -1, -1):
        if (num!=0):
          temp+=pow(2, j)
          num-=1
      mask_list.append(temp)
    return mask_list

def addr_to_string(addr, mask=None):
    """
    converts addr from [10,0,0,1] and mask 24 to string "10.0.0.1/24"
    """
    ip_addr=str(addr[0])+"."+str(addr[1])+"."+str(addr[2])+"."+str(addr[3])
    if (type(mask)!=type(None)):
        ip_addr+="/"
        ip_addr+=str(mask)
    return ip_addr






