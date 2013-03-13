import sys, os, copy, general_functions

MASK=255
MAX_NUM=65535

class Error_Message:
    def __init__(self, x, y):
        self.counter=x
        self.message=y

Protocol={'ah': 51, 'eigrp': 88, 'esp': 50, 'gre': 47, 'icmp': 1, 
          'igmp': 2, 'ip': 0, 'ip-in-ip': 4, 'ospf': 89, 'pim': 103,
          'tcp':6, 'udp':17}

class Rule:
    """
    number starts with ZERO
    """
    number=0
    action="deny"
    protocol="tcp"
    src_addr=[0,0,0,0]
    src_mask=[0,0,0,0]
    src_port=0
    src_port_operator=""
    dst_addr=[0,0,0,0]
    dst_mask=[0,0,0,0]
    dst_port=0
    dst_port_operator=""
    dynamic=""
    time_out=0
    established=False
    precedence=0
    tos=0
    log=False
    log_input=False
    time_range=""
    
    def set_number(self, num):
        self.number=num
        return True

    def set_dynamic(self, dyn, index):
        if (dyn=="dynamic"):
            self.dunamic = dyn
            index[0]+=2
            return True
        return False

    def set_time_out(set, time, index):
        if (time=="timeout"):
            if time.isdigit():
                self.time_out=int(time)
                index[0]+=2;
            else:
                return False
        return True

    def set_action(self, act, index):
        #print "act=", act
        if ((act=="permit")|(act=="deny")):
            self.action=act
            index[0]+=1
            print "index=", index
            return True
        else:
            return False
         
    def set_protocol(self, proto, index):
        #print "protocol=", proto, index
        if (proto in Protocol.keys()):
            self.protocol=Protocol.get(proto)
            index[0]+=1
            return True
        return False

    
    def set_src_addr(self, addr, index):
        #print "src address=", addr, index
        if (len(addr)==4):
            for n in xrange(0,4):
                if (not addr[n].isdigit()):
                    return False
            index[0]+=1
            self.src_addr=list(addr)
            for i in xrange(len(self.src_addr)):
                self.src_addr[i]=int(self.src_addr[i])
            return True
        else:
            return False
        

    def set_src_mask(self, mask, index):
        #print "src mask=", mask, index
        if (len(mask)==4):
            index[0]+=1
            for n in xrange (0,4):
                if (mask[n].isdigit()):
                    mask[n]=(MASK-int(mask[n]))
                    self.src_addr[n]=self.src_addr[n]&mask[n] 
                else:
                    return False
            self.src_mask=general_functions.convert_mask(mask)
            return True
        else:
            return False
        
        
    def set_src_port(self, port, index):
        verif=set(["any", "eq", "gt", "host", "lt", "neq", "range"] ) #definition between eq and host
        i=index[0]
        self.src_port_operator=0
        if not (port[i].isdigit()):
            if (port[i] in verif):
                self.src_port_operator=port[i]
                index[0]+=1
                if (self.src_port_operator=="range"):# zdes' dolghen byt massiv
                    if ((port[i].isdigit()) and (int(port[i])>=0) and (int(port[i])<=MAX_NUM) and \
                        (port[i+1].isdigit()) and (int(port[i+1])>=0) and (int(port[i+1])<=MAX_NUM)):
                        self.src_port=list(port[i],port[i+1])
                        index[0]+=2
                    else:
                        return False    
                elif (not (self.src_port_operator=="any"))&(port[i].isdigit()):    
                    if (int(port[i])>=0)&(int(port[i])<=MAX_NUM):
                        self.src_port=int(port[i])
                        index[0]+=1
                    else:
                        return False
            else:
                return False
        else:
            self.src_port=int(port[i])
            index[0]+=1
            return True
        return True

    def set_dst_addr(self, addr, index):
        if (len(addr)==4):
            for n in xrange(0,4):
                if (addr[n].isdigit()):
                    #rule.src_addr[n]=temp_addr[n]
                    pass
                else:
                    return False
            index[0]+=1
            self.dst_addr=list(addr)
            for x in xrange(len(self.dst_addr)):
                self.dst_addr[x]=int(self.dst_addr[x])
        else:
            return False
        return True

    def set_dst_mask(self, mask, index):
        if (len(mask)==4):
            index[0]+=1
            for n in xrange (0,4):
                if (mask[n].isdigit()):
                    mask[n]=MASK-int(mask[n])
                    self.dst_addr[n]=self.dst_addr[n]&mask[n]
                else:
                    return False
        else:
            return False
        self.dst_mask=general_functions.convert_mask(mask)
        return True

    def set_dst_port(self, port, index):
        i=index[0]
        verif=set(["any", "eq", "gt", "host", "lt", "neq", "range"])
        if not (port[i].isdigit()):
            if (port[i] in verif):
                
                self.dst_port_operator=port[i]
                index[0]+=1
                if (self.dst_port_operator=="range"):# zdes' dolghen byt massiv
                    if ((port[i].isdigit()) and (int(port[i])>=0) and \
                        (int(port[i])<=MAX_NUM) and (port[i+1].isdigit()) and \
                        (int(port[i+1])>=0) and (int(port[i+1])<=MAX_NUM)):
                        self.dst_port=list(port[i],port[i+1])
                        index[0]+=2
                    else:
                        return False    
                elif (not (self.dst_port_operator=="any")) and (port[i].isdigit()):    
                    if (int(port[i])>=0) and (int(port[i])<=MAX_NUM):
                        self.dst_port=int(port[i])
                        index[0]+=1
                    else:
                        return False
            else:
                return False
        else:
            self.dst_port=int(port[i])
            index[0]+=1
        return True

    def set_precedence(self, prec, index):
        if (prec=="precedence"):
            self.precedence=int(prec[index]+1)
            index[0]+=2

    def set_tos(self, tos, index):
        i=index[0]
        if(tos[i]=="tos"):
            self.tos=int(tos[i]+1)
            index[0]+=2

    def set_log(self, log, index):
        if(log=="log"):
            self.log=True
            index[0]+=1
        elif(log=="log-input"):
            rule.log_input=True
            index[0]+=1

    def set_time_range(self, time, index):
        i=index[0]
        if(time[i]=="time-range"):
            self.time_range=copy.deepcopy(time[i+1]) #need deep copy!!!
            index[0]+=2


class Firewall_Manager:
    
    def parse(self, filename, rule_list,):
        try:
            counter=0    
            f=open(filename, "r").readlines()
            for i in f:
                rule=Rule()
                rule.set_number(counter)
                counter+=1
                index=[0]
                protocol=""
                i=i.strip()
                j=i.split()
                length=len(j)
                print j

                #dynamic
                if (rule.set_dynamic(j[index[0]], index)):
                    if not (rule.set_time_out(j[index[0]], index)):
                        raise Error_Message(counter, "Error in time-out field, rule")
                    
                #action
                if not (rule.set_action(j[index[0]], index)):
                   raise Error_Message(counter, "Error in action type, rule")

                #protocol
                protocol=j[index[0]]
                if not (rule.set_protocol(j[index[0]], index)):
                    raise Error_Message(counter, "Error in protocol type, rule")

                #src_addr
                if not (rule.set_src_addr(j[index[0]].split("."), index)):
                    raise Error_Message(counter, "Error in src address, rule")     
                    
                #src_mask    
                if not (rule.set_src_mask(j[index[0]].split("."), index)):
                    raise Error_Message(counter, "Error in src mask, rule")

                #src_port
                if (protocol=="tcp")|(protocol=="udp")|(protocol=="icmp")|(protocol=="ip"):
                    if not (rule.set_src_port(j, index)):
                        raise Error_Message(counter, "Error in src port, rule")
                    
                #dst_addr
                if not (rule.set_dst_addr(j[index[0]].split("."), index)):
                    raise Error_Message(counter, "Error in dst address, rule")
                    
                #dst_mask
                if not (rule.set_dst_mask(j[index[0]].split("."), index)):
                    raise Error_Message(counter, "Error in src mask, rule")

                #dst_port
                if (protocol=="tcp")|(protocol=="udp"):
                    if not (rule.set_dst_port(j, index)):
                        raise Error_Message(counter, "Error in dst port, rule")

                if (protocol=="icmp"):
                    pass # there need be [icmp-type [icmp-code] |icmp-message]

                if (index<length):
                    if (protocol=="tcp")&(j[index[0]]=="established"):
                        rule.established=True
                        index[0]+=1

                if (index<length):
                    rule.set_precendence(j, index)

                if (index<length):
                    rule.set_tos(j, index)

                if (index<length):
                    rule.set_log(j, index)
                        
                if (index<length):
                    rule.set_time_range(j, index)
                    
                #add_rule
                rule_list.append(rule)

        except(Error_Message), err:
            print err.message, err.counter
            #exit()
        print "Done!"
        #print "============================="
        #for i in xrange(len(rule_list)):
        #    print rule_list[i].src_port_operator
        #print "============================="

    def protocol_index(self, rule):
        if (rule.protocol=="tcp"):
            return 0
        elif (rule.protocol=="udp"):
            return 1
        elif (rule.protocol=="icmp"):
            return 2
        else:
            return 3


    def check_for_intra_anomaly(self, x, y):
        #print "*x.src_addr", x.src_addr
        #print "*y.src_addr", y.src_addr, y.src_mask
        #print "*x.dst_addr", x.dst_addr
        #print "*y.dst_addr", y.dst_addr, y.dst_mask
        
        
        src_addr_temp1=general_functions.addr_subset(x.src_addr, y.src_addr, y.src_mask)
        src_addr_temp2=general_functions.addr_subset(y.src_addr, x.src_addr, x.src_mask)
        dst_addr_temp1=general_functions.addr_subset(x.dst_addr, y.dst_addr, y.dst_mask)
        dst_addr_temp2=general_functions.addr_subset(y.dst_addr, x.dst_addr, x.dst_mask)
        src_port_temp1=general_functions.src_port_subset(x, y)
        src_port_temp2=general_functions.src_port_subset(y, x)
        dst_port_temp1=general_functions.dst_port_subset(x, y)
        dst_port_temp2=general_functions.dst_port_subset(y, x)
        if (src_addr_temp1==2):
            if (src_port_temp1==2):
                if (dst_addr_temp1==2):
                    if (dst_port_temp1==2):# ->exact
                        return "exact"
                    elif (dst_port_temp1==1): # ->subset
                        if (x.action==y.action):
                            return "redundancy"
                        else:
                            return "shadowing"
                    elif (dst_port_temp2==1): # ->superset
                        if (x.action==y.action):
                            return "redundancy"
                        else:
                            return "generalisation"
                    else:
                        return "none"
                        
                elif (dst_addr_temp1==1): #->subset
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->subset
                        if (x.action==y.action):
                            return "redundancy"
                        else:
                            return "shadowing"
                    elif (dst_port_temp2==1):# ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    else:
                        return "none"

                elif (dst_addr_temp2==1): #->superset
                    if (dst_port_temp1==1):# ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->superset
                        if (x.action==y.action):
                            return "redundancy"
                        else:
                            return "generalisation"
                    else:
                        return "none"
                else:
                    return "none"
                    
            elif (src_port_temp1==1):# ->subset
                if (dst_addr_temp1!=-1): #->subset
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->subset
                        if (x.action==y.action):
                            
                            return "redundancy"
                        else:
                            return "shadowing"
                    elif (dst_port_temp2==1):# ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    else:
                        return "none"
                elif (dst_addr_temp2!=-1): #->correlated
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    else:
                        return "none"
                else:
                    return "none"
            elif (src_port_temp2==1):# ->superset
                if (dst_addr_temp1==1): #->correlated
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    else:
                        return "none"
                elif (dst_addr_temp2==1)|(dst_addr_temp2==2): #->superset
                    if (dst_port_temp1==1):# ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->superset
                        if (x.action==y.action):
                            return "redundancy"
                        else:
                            return "generalisation"
                    else:
                        return "none"
                else:
                    return "none"
            else:
                return "none"
                
#################################################################################
        elif (src_addr_temp1==2)|(src_addr_temp1==1): # ->subset
            if (src_port_temp1==1)|(src_port_temp1==2): # -> subset
                if (dst_addr_temp1!=-1): #  ->subset
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): #->subset
                        if (x.action==y.action):
                            return "redundancy"
                        else:
                            return "shadowing"
                    elif ((dst_port_temp2==1)): #->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    else:
                        return "none"         
                elif (dst_addr_temp2!=-1): # ->correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    elif ((dst_port_temp2==1)|(dst_port_temp2==2)):#->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    else:
                        return "none"
                else:
                    return "none"
        #########################################################################################        
            elif ((src_port_temp2==1)): # ->correlated 
                if (dst_addr_temp1==1)|(dst_addr_temp1==2): # ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        if (x.action==y.action):
                            return "none" 
                        else:
                            return "correlation" 
                    elif ((dst_port_temp2==1)): #->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    else:
                        return "none"
                elif (dst_addr_temp2==1): # ->correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    elif ((dst_port_temp2==1)): #->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    else:
                        return "none"
                else:
                    return "none"
            else:
                return "none"
################################################################################################# 
        elif (src_addr_temp2==2)|(src_addr_temp2==1): # ->superset
            
            if ((src_port_temp1==1)): # ->correlated
                if (dst_addr_temp1==1)|(dst_addr_temp1==2): #  ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): #->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    elif ((dst_port_temp2==1)): #->correlated
                        if (x.action==y.action):
                            return "none" 
                        else:
                            return "correlation"
                    else:
                        return "none"         
                elif (dst_addr_temp2==1): # -> correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    elif ((dst_port_temp2==1)):#-> correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    else:
                        return "none"
                else:
                    return "none"
############################################################################################       
            elif ((src_port_temp2==1)|(src_port_temp2==2)): # -> superset
                if (dst_addr_temp1==1): # ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        if (x.action==y.action):
                            return "none" 
                        else:
                            return "correlation" 
                    elif ((dst_port_temp2==1)): #->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    else:
                        return "none"
                elif (dst_addr_temp2==1)|(dst_addr_temp2==2): # ->superset
                    if ((dst_port_temp1==1)): # ->correlated
                        if (x.action==y.action):
                            return "none"
                        else:
                            return "correlation"
                    elif ((dst_port_temp2==1)|(dst_port_temp2==2)): #->superset
                        if (x.action==y.action):
                            return "redundancy"
                        else:
                            return "generalisation"
                    else:
                        return "none"
                else:
                    return "none"
            else:
                return "none"
        else:
            return "none"


    def check_in_redundancy_case(self, rule_tree, rule, proto):
        """
        returns
            True if redundancy
            False in other case
        """
        #print "check_in_redundancy_case"
        y=rule
        for a in xrange(len(rule_tree[proto])): # perebor po src_addr 
            for b in xrange(len(rule_tree[proto][a])): # perebor po src_port
                for c in xrange(len(rule_tree[proto][a][b])): # perebor po dst_addr
                    for d in xrange(len(rule_tree[proto][a][b][c])): # perebor po dst_port
                        for e in xrange(len(rule_tree[proto][a][b][c][d])): # perebor po number
                            x=rule_tree[proto][a][b][c][d][e]
                            if (y.number<x.number):
                                #print "Compare ", x.number+1, y.number+1
                                state=self.check_for_intra_anomaly(x,y)
                                #print state
                                if (((state=="generalisation")|(state=="correlation"))&(x.action!=y.action)):
                                    return False
        return True


    def find_anomaly(self, rule_tree, rule):
        """
        returns -1 if current rule was deleted
        """
        proto=self.protocol_index(rule)
        for j in xrange(len(rule_tree[proto])): # perebor po src_addr 
            for k in xrange(len(rule_tree[proto][j])): # perebor po src_port
                for l in xrange(len(rule_tree[proto][j][k])): # perebor po dst_addr
                    for m in xrange(len(rule_tree[proto][j][k][l])): # perebor po dst_port
                        for n in xrange(len(rule_tree[proto][j][k][l][m])): # perebor po number
                            x=rule
                            y=rule_tree[proto][j][k][l][m][n]
                            #print "Check for", x.number+1, y.number+1
                            #print x.action, x.src_addr, x.src_mask, x.dst_addr, x.dst_mask
                            #print y.action, y.src_addr, y.src_mask, y.dst_addr, y.dst_mask
                            state=self.check_for_intra_anomaly(x,y)
                            #raw_input()
                            #print x.state, y.state
                            if (state=="exact"):
                               # print "Rule deleted in exact", x.number+1
                                return False
                            if (state=="redundancy"):
                                if (self.check_in_redundancy_case(rule_tree, y, proto)):
                                    #print "Rule deleted in redundancy", y.number+1
                                    del rule_tree[proto][j][k][l][m][n] #delete y
                                    continue
                            elif (state=="shadowing"):
                                #print "Rule deleted in shadowing", x.number+1
                                return False #delete x
                                                        
        return True
                            

    def insert_rule_in_tree (self, rule_tree, rule):

        proto=self.protocol_index(rule)    

        if (len(rule_tree[proto])==0):
            #rule.number=number
            rule_tree[proto].append([[[[rule]]]])
            return

        #if (self.find_anomaly(rule_tree, rule)==-1):
        #    return

        src_addr_index=-1; src_port_index=-1; dst_addr_index=-1; dst_port_index=-1; number_index=-1
        src_addr_subset=False; src_port_subset_flag=False; dst_addr_subset=False; dst_port_subset_flag=False
        no_src_addr=False; no_dst_addr=False; no_src_port=False; no_dst_port=False
        done=False
        #rule.number=number
        
        for j in xrange(len(rule_tree[proto])): # perebor po src_addr 
            for k in xrange(len(rule_tree[proto][j])): # perebor po src_port
                for l in xrange(len(rule_tree[proto][j][k])): # perebor po dst_addr
                    for m in xrange(len(rule_tree[proto][j][k][l])): # perebor po dst_port
                        for n in xrange(len(rule_tree[proto][j][k][l][m])): # perebor po number
                            x=rule
                            y=rule_tree[proto][j][k][l][m][n]
                            if (y.src_addr==rule.src_addr):
                                src_addr_index=j
                                #print "   Sovpadenie src_addr"
                                if (y.src_port==rule.src_port):
                                    src_port_index=k
                                    #print "   Sovpadenie src_port"
                                    if (y.dst_addr==rule.dst_addr):
                                        dst_addr_index=l
                                        #print "   Sovpadenie dst_addr", y.dst_addr, rule.dst_addr
                                        if (y.dst_port==rule.dst_port):
                                            dst_port_index=m
                                            done=True
                                            #print "   Sovpadenie dst_port"
                                            break
                                        elif (general_functions.dst_port_subset(rule, y)==1):
                                            #print "Subset dst port"
                                            dst_port_subset_flag=True
                                            dst_port_index=m
                                            done=True
                                            break
                                        else:
                                            no_dst_port=True
                                            #print "no_number"
                                    elif (general_functions.addr_subset(rule.dst_addr, y.dst_addr, y.dst_mask)==1):
                                        #print "Subset dst addr"
                                        dst_addr_subset=True
                                        done=True
                                        dst_addr_index=l
                                    else:
                                        no_dst_addr=True
                                        no_dst_port=True
                                        #print "no dst_addr"
                                elif (general_functions.src_port_subset(rule, y)==1):
                                    #print "Subset src port"
                                    src_port_subset_flag=True
                                    done=True
                                    src_port_index=k
                                else:
                                    no_src_port=True
                                    no_dst_addr=True
                                    no_dst_port=True
                                    #print "no_src_port"
                            elif (general_functions.addr_subset(rule.src_addr, y.src_addr, y.src_mask)==1):
                                #print "Subset src addr"
                                src_addr_subset=True
                                done=True
                                src_addr_index=j
                            else:
                                no_src_addr=True
                                no_src_port=True
                                no_dst_addr=True
                                no_dst_port=True
                                #print "no_src_addr"
                                                
                            if (no_dst_port)|(done):
                                no_dst_port=False
                                break
                        if (dst_port_index!=-1)|(no_dst_addr)|(done):
                            no_dst_addr=False
                            break
                    if (dst_addr_index!=-1)|(no_src_port)|(done):
                        no_src_port=False
                        break   
                if (src_port_index!=-1)|(no_src_addr)|(done):
                    no_src_addr=False
                    break
            if (src_addr_index!=-1)|(done):
                done=False
                break

        if (src_addr_index!=-1):
            if (src_port_index!=-1):
                if (dst_addr_index!=-1):
                    if(dst_port_index!=-1):
                        #print "Full insert"
                        if (dst_port_subset_flag):
                            rule_tree[proto][src_addr_index][src_port_index][dst_addr_index].insert(dst_port_index, [rule])
                        else:    
                            rule_tree[proto][src_addr_index][src_port_index][dst_addr_index][dst_port_index].append(rule)
                    else:
                        #print "insert [proto][src_addr_index][src_port_index][dst_addr_index]"
                        if (dst_addr_subset):
                            rule_tree[proto][src_addr_index][src_port_index].insert(dst_addr_index,[[rule]])
                        else:
                            rule_tree[proto][src_addr_index][src_port_index][dst_addr_index].append([rule])
                else:
                    #print "insert [proto][src_addr_index][src_port_index]"
                    if (src_port_subset_flag):
                        rule_tree[proto][src_addr_index].insert(src_port_index,[[[rule]]])
                    else:
                        rule_tree[proto][src_addr_index][src_port_index].append([[rule]])
            else:
                #print "insert [proto][src_addr_index]"
                if (src_addr_subset):
                    rule_tree[proto].insert(src_addr_index,[[[[rule]]]])
                else:
                    rule_tree[proto][src_addr_index].append([[[rule]]])  
        else:
            #print "insert [proto]"
            rule_tree[proto].append([[[[rule]]]])



    def tree_build(self, rule_list, rule_tree):
        self.insert_rule_in_tree (rule_tree, rule_list[0])
        for i in xrange (1, len(rule_list)):
            if (not self.find_anomaly(rule_tree, rule_list[i])):
                continue
            self.insert_rule_in_tree (rule_tree, rule_list[i])
        #Correct_Order(rule_tree)


    def merge_trees(self, rule_tree_1, rule_tree_2):
        """
        add rule_tree_2 to rule_tree_1
        """
        for a in xrange(len(rule_tree_2)):# perebor po proto
            for b in xrange(len(rule_tree_2[a])): # perebor po src_addr 
                for c in xrange(len(rule_tree_2[a][b])): # perebor po src_port
                    for d in xrange(len(rule_tree_2[a][b][c])): # perebor po dst_addr
                        for e in xrange(len(rule_tree_2[a][b][c][d])): # perebor po dst_port
                            for f in xrange(len(rule_tree_2[a][b][c][d][e])):# perebor po number
                                rule=rule_tree_2[a][b][c][d][e][f]
                                self.insert_rule_in_tree(rule_tree_1, rule)
                                
            
    def Check_For_Inter_Anomaly(self, x, y):
        """ x-upstream fw
            y-downstream fw
        """
        src_addr_temp1=general_functions.addr_subset(x.src_addr, y.src_addr, y.src_mask)
        src_addr_temp2=general_functions.addr_subset(y.src_addr, x.src_addr, y.src_mask)
        dst_addr_temp1=general_functions.addr_subset(x.dst_addr, y.dst_addr, y.dst_mask)
        dst_addr_temp2=general_functions.addr_subset(y.dst_addr, x.dst_addr, x. dst_mask)
        src_port_temp1=general_functions.src_port_subset(x, y)
        src_port_temp2=general_functions.src_port_subset(y, x)
        dst_port_temp1=general_functions.dst_port_subset(x, y)
        dst_port_temp2=general_functions.dst_port_subset(y, x)

        if (x.src_addr==y.src_addr)&(x.src_port==y.src_port)&\
           (x.dst_addr==y.dst_addr)&(x.dst_port==y.dst_port)&\
           (x.action==y.action):
            return "exact"
        if (src_addr_temp1>=1)&(dst_addr_temp1>=1)&\
           (src_port_temp1>=1)&(dst_port_temp1>=1)&\
           (x.action=="permit")&(y.action=="deny"):
            return "spurious"
        if (src_addr_temp2>=1)&(dst_addr_temp2>=1)&\
           (src_port_temp2>=1)&(dst_port_temp2>=1)&\
           (x.action=="deny")&(y.action=="permit"):
            return "shadowing"
        return "none"


    def Build_Single_Firewall(self, nodes_from_A_to_B, single_fw):
        #print "We are in build"
        is_empty=True
        anomaly_flag=False
        for i in xrange(len(nodes_from_A_to_B)):
            if (nodes_from_A_to_B[i][0]._label==3):
            
                if (is_empty):
                    single_fw[:]=copy.deepcopy(nodes_from_A_to_B[i][0]._temp_rule_tree)
                    is_empty=False
                    continue
                
                for proto in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree)): # perebor po proto
                    for j in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree[proto])): # perebor po src_addr 
                        for k in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree[proto][j])): # perebor po src_port
                            for l in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree[proto][j][k])): # perebor po dst_addr
                                for m in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree[proto][j][k][l])): # perebor po dst_port
                                    for n in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree[proto][j][k][l][m])): # perebor po number
                                        y=nodes_from_A_to_B[i][0]._temp_rule_tree[proto][j][k][l][m][n]

                                        for a in xrange(len(single_fw)):# perebor po proto
                                            for b in xrange(len(single_fw[a])): # perebor po src_addr 
                                                for c in xrange(len(single_fw[a][b])): # perebor po src_port
                                                    for d in xrange(len(single_fw[a][b][c])): # perebor po dst_addr
                                                        for e in xrange(len(single_fw[a][b][c][d])): # perebor po dst_port
                                                            for f in xrange(len(single_fw[a][b][c][d][e])): # perebor po number
                                                                x=single_fw[a][b][c][d][e][f]
                                                                anomaly_flag=False
                                                                #print "Check" , x.number+1 , y.number+1
                                                                anomaly=self.Check_For_Inter_Anomaly(x, y)
                                                                #print anomaly
                                                                if (anomaly=="exact"):
                                                                    anomaly_flag=True
                                                                elif (anomaly=="shadowing"):
                                                                    #print "Deleted rule", y.number+1
                                                                    anomaly_flag=True
                                                                    break
                                                                elif (anomaly=="spurious"):
                                                                    pass
                                                                    #print "Deleted rule", x.number+1
                                                                    #del single_fw[a][b][c][d][e][f]
                                                                else:
                                                                    pass
                                                                    #print "No anomaly"
                                                                if anomaly_flag:
                                                                    break
                                                            if anomaly_flag:
                                                                break
                                                        if anomaly_flag:
                                                            break
                                                    if anomaly_flag:
                                                        break
                                                if anomaly_flag:
                                                    break
                                            if anomaly_flag:
                                                break
                                                

                                        if not anomaly_flag:
                                            #print "Append with rule", y.number+1
                                            #nodes_from_A_to_B[i][0]._temp_rule_tree[proto][j][k][l][m][n].number=num+y.number
                                            #print nodes_from_A_to_B[i][0]._rule_tree[proto][j][k][l][m][n].number, num
                                            #num+=1
                                            self.insert_rule_in_tree(single_fw, nodes_from_A_to_B[i][0]._temp_rule_tree[proto][j][k][l][m][n])
                                        else:
                                            anomaly_flag=False

                #print "##################################################Single FireWall"
                #general_functions.Tree_Print(single_fw)
                #num+=10
                #print "##################################################"
                

                            
    def check_for_inter_anomaly_old(self, x, y):
        def exact(act1, act2):
            #print "act1=", act1
            #print "act2=", act2
            if (act1=="permit")&(act2=="deny"):
                anomaly="shadowing"
            elif (act1=="deny")&(act2=="permit"):
                anomaly="spuriousness"
            elif (act1==act2):
                anomaly="redundancy"
            return anomaly
            
        def subset(act1, act2):
            if (act1=="permit")&(act2=="deny"):
                anomaly="shadowing"
            elif(act2=="accept"):
                anomaly="spuriousness"
            else:
                anomaly="redundancy"
            return anomaly

        def superset(act1, act2):
            if (act1=="accept"):
                anomaly="shadowing"
            else:
                anomaly="spuriousness"

        def correlation(act1, act2):
            anomaly="correlation"
            return anomaly

        
        src_addr_temp1=addr_subset(x.src_addr, y.src_mask)
        src_addr_temp2=addr_subset(y.src_addr, x.src_mask)
        dst_addr_temp1=addr_subset(x.dst_addr, y.dst_mask)
        dst_addr_temp2=addr_subset(y.dst_addr, x.dst_mask)
        src_port_temp1=src_port_subset(x, y)
        src_port_temp2=src_port_subset(y, x)
        dst_port_temp1=dst_port_subset(x, y)
        dst_port_temp2=dst_port_subset(y, x)

        if (src_addr_temp1==2):
            if (src_port_temp1==2):
                if (dst_addr_temp1==2):
                    if (dst_port_temp1==2):# ->exact
                        anomaly=exact(x.action, y.action)
                    elif (dst_port_temp1==1): # ->subset
                        anomaly=subset(x.action, y.action)
                    elif (dst_port_temp2==1): # ->superset
                        anomaly=superset(x.action, y.action)
                    else:
                        x.state="none"
                        
                elif (dst_addr_temp1==1): #->subset
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->subset
                        anomaly=subset(x.action, y.action)
                    elif (dst_port_temp2==1):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"

                elif (dst_addr_temp2==1): #->superset
                    if (dst_port_temp1==1):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->superset
                        anomaly=superset(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
                    
            elif (src_port_temp1==1):# ->subset
                if (dst_addr_temp1): #->subset
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->subset
                        anomaly=subset(x.action, y.action)
                    elif (dst_port_temp2==1):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                elif (dst_addr_temp2): #->correlated
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
            elif (src_port_temp2==1):# ->superset
                if (dst_addr_temp1==1): #->correlated
                    if (dst_port_temp1==1)|(dst_port_temp1==2):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                elif (dst_addr_temp2==1)|(dst_addr_temp2==2): #->superset
                    if (dst_port_temp1==1):# ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif (dst_port_temp2==1)|(dst_port_temp2==2):# ->superset
                        anomaly=superset(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
            else:
                none
                
#################################################################################
        elif (src_addr_temp1==2)|(src_addr_temp1==1): # ->subset
            if (src_port_temp1==1)|(src_port_temp1==2): # -> subset
                if (dst_addr_temp1): #  ->subset
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): #->subset
                        anomaly=subset(x.action, y.action)
                    elif ((dst_port_temp2==1)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"         
                elif (dst_addr_temp2): # ->correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)|(dst_port_temp2==2)):#->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
        #########################################################################################        
            elif ((src_port_temp2==1)): # ->correlated 
                if (dst_addr_temp1==1)|(dst_addr_temp1==2): # ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                elif (dst_addr_temp2==1): # ->correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
            else:
                x.state="none"
################################################################################################# 
        elif (src_addr_temp2==2)|(src_addr_temp2==1): # ->superset
            
            if ((src_port_temp1==1)): # ->correlated
                if (dst_addr_temp1==1)|(dst_addr_temp1==2): #  ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"         
                elif (dst_addr_temp2==1): # -> correlated 
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)):#-> correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
############################################################################################       
            elif ((src_port_temp2==1)|(src_port_temp2==2)): # -> superset
                if (dst_addr_temp1==1): # ->correlated
                    if ((dst_port_temp1==1)|(dst_port_temp1==2)): # ->correlated
                        anomaly=correlation(x.action, y.action) 
                    elif ((dst_port_temp2==1)): #->correlated
                        anomaly=correlation(x.action, y.action)
                    else:
                        x.state="none"
                elif (dst_addr_temp2==1)|(dst_addr_temp2==2): # ->superset
                    if ((dst_port_temp1==1)): # ->correlated
                        anomaly=correlation(x.action, y.action)
                    elif ((dst_port_temp2==1)|(dst_port_temp2==2)): #->superset
                        anomaly=superset(x.action, y.action)
                    else:
                        x.state="none"
                else:
                    x.state="none"
            else:
                x.state="none"
        else:
            x.state="none"

            
    def append_list(self, rule_list_ups, rule_list_downs):
        for i in xrange (len (rule_list_ups)):
            for j in xrange (len (rule_list_downs)):
                x=rule_list_ups[i]
                y=rule_list_downs[j]
                if (x.protocol==y.protocol):
                    self.check_for_inter_anomaly(x, y)#check for inter anomaly
