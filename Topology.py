from collections import defaultdict
import copy
import fw_policy
import graph 
import general_functions

PRIORITY=32500 # maximum priority

class Entry:
    def __init__(self, addr, mask, port):
        self.ip_addr=general_functions.addr_to_list(addr)
        self.ip_mask=general_functions.addr_to_list(mask)
        self.port=port

class Switch (object): #switch
    _next_num = 0
    def __init__ (self):
        self._label=1
        self._num = self.__class__._next_num
        self.__class__._next_num += 1
        self._fw_Manager=fw_policy.Firewall_Manager()
        
    def __repr__ (self):
        return "Node1 #" + str(self._num)

    def __eq__(self,y):
        if (self._label==y._label)&(self._num==y._num):
            return True
        return False

    def __ne__(self,y):
        if (self._label!=y._label)|(self._num!=y._num):
            return True
        return False


class Host (object): #host
    _next_num = 0
            
    def __init__ (self, ip_addr, ip_mask, default_gw):
        self._label=2
        self._ip_addr=general_functions.addr_to_list(ip_addr)
        self._ip_mask=general_functions.addr_to_list(ip_mask)
        for i in xrange(0,4):
            self._ip_addr[i]=(self._ip_addr[i])&(self._ip_mask[i])
        self._default_gw=general_functions.addr_to_list(default_gw)
        self.dpid=0 # id of OF switch (in new topology)
        self._num = self.__class__._next_num
        self.__class__._next_num += 1
        
        self._new_rule_tree=[[],[],[],[]]
        self._is_empty=True # is rule_tree empty
        self._current_number_of_rules=0
  
    def __repr__ (self):
        return "Node2 #" + str(self._num)

    def __eq__(self, y):
        if (self._label==y._label)&(self._num==y._num):
            return True
        return False

    def __ne__(self,y):
        if (self._label!=y._label)|(self._num!=y._num):
            return True
        return False

    def set_dpid(self, dpid):
        self.dpid=dpid


class Firewall (object): #Firewall
    _next_num = 0
    
    def __init__ (self, filename, fw_manager):
        self._label=3
        self._rule_tree=[[],[],[],[]] # complete rule tree
        self._temp_rule_tree=[[],[],[],[]] # rule tree for each two nodes
        self._num = self.__class__._next_num
        self.__class__._next_num += 1
        self._rule_list=[]
        fw_manager.parse(filename, self._rule_list)
        #print "Start Building!"
        fw_manager.tree_build(self._rule_list, self._rule_tree)
        #print "***********************************************"
        #general_functions.Tree_Print(self._rule_tree)
        #print "***********************************************"
      
  
    def __repr__ (self):
        return "Node3 #" + str(self._num)

    def __eq__(self, y):
        if (self._label==y._label)&(self._num==y._num):
            return True
        return False

    def __ne__(self,y):
        if (self._label!=y._label)|(self._num!=y._num):
            return True
        return False

class OF_Switch (object): #host
    _next_num = 0
    priority=PRIORITY
    
    def __init__ (self, port_number, dpid):
        self._label=4
        self.port_number=port_number # average number of ports on switch
        self.dpid=dpid # id of OF switch (in new topology)
        self.entry_list=[]
        self.was_used=False # has it already discovered in new topology
        self._num = self.__class__._next_num
        self.__class__._next_num += 1
        self.rule_tree=[[],[],[],[]]
        self.is_empty=True # is rule_tree empty?
        self.connectionTable=0
        self.macTable=[] #[(port1,mac1), ..., (portn, macn)]
        self.constant_flow_priority=PRIORITY
        self.permanent_flow_priority=PRIORITY+1
  
    def __repr__ (self):
        return "Node4 #" + str(self._num)

    def __eq__(self, y):
        if (self._label==y._label)&(self._num==y._num):
            return True
        return False

    def __ne__(self,y):
        if (self._label!=y._label)|(self._num!=y._num):
            return True
        return False
    
    def add_entry(self, entry):
        self.entry_list.append(entry) 

    def append_tree(self, rule_tree, fw_manager):
        if (self.is_empty):
            self.rule_tree=copy.deepcopy(rule_tree)
            self.is_empty=False
        else:
            fw_manager.merge_trees(self.rule_tree, rule_tree)
        return


class Topology:
    
    _g=graph.Graph()
    _new_g=graph.Graph()
    _host_nodes=[]
    _switch_nodes=[]
    _of_switch_nodes={}
    _firewall_nodes=[]
    
    def __init__(self):

        reload (general_functions)
        reload (fw_policy)
        self.fw_manager=fw_policy.Firewall_Manager()
        
        # Our Topology

        fn1=Firewall("ext/Firewall_A", self.fw_manager); self._g.add(fn1); self._firewall_nodes.append(fn1)#firewall
        fn2=Firewall("ext/Firewall_B", self.fw_manager); self._g.add(fn2); self._firewall_nodes.append(fn2)#firewall
        fn3=Firewall("ext/Firewall_C", self.fw_manager); self._g.add(fn3); self._firewall_nodes.append(fn3)#firewall

        n1=Host("192.168.20.2", "255.255.255.0", "192.168.20.254"); self._g.add(n1); self._host_nodes.append(n1)#host
        #n1=Host("10.0.0.1", "255.255.255.224", "10.0.0.5"); self._g.add(n1); self._host_nodes.append(n1)#host
        n2=Host("10.0.0.33", "255.255.255.248", "10.0.0.35"); self._g.add(n2); self._host_nodes.append(n2)#host
        n3=Host("192.168.1.2", "255.255.255.0", "192.168.1.254"); self._g.add(n3); self._host_nodes.append(n3)#host
        #n3=Host("192.168.0.1", "255.255.255.192", "192.168.0.5"); self._g.add(n3); self._host_nodes.append(n3)#host
        n4=Host("192.168.0.65", "255.255.255.252", "192.168.0.66"); self._g.add(n4); self._host_nodes.append(n4)#host
        n5=Host("172.16.0.1", "255.255.255.240", "172.16.0.5"); self._g.add(n5); self._host_nodes.append(n5)#host
        n6=Host("172.16.0.17", "255.255.255.248", "172.16.0.20"); self._g.add(n6); self._host_nodes.append(n6)#host
        n7=Host("172.16.0.25", "255.255.255.252", "172.16.0.26"); self._g.add(n7); self._host_nodes.append(n7)#host (Internet)

        sn0=Switch(); self._g.add(sn0); self._switch_nodes.append(sn0) #switch
        sn1=Switch(); self._g.add(sn1); self._switch_nodes.append(sn1) #switch
        sn2=Switch(); self._g.add(sn2); self._switch_nodes.append(sn2) #switch
        sn3=Switch(); self._g.add(sn3); self._switch_nodes.append(sn3) #switch
        sn4=Switch(); self._g.add(sn4); self._switch_nodes.append(sn4) #switch
        sn5=Switch(); self._g.add(sn5); self._switch_nodes.append(sn5) #switch
        sn6=Switch(); self._g.add(sn6); self._switch_nodes.append(sn6) #switch
        sn7=Switch(); self._g.add(sn7); self._switch_nodes.append(sn7) #switch
        sn8=Switch(); self._g.add(sn8); self._switch_nodes.append(sn8) #switch
        sn9=Switch(); self._g.add(sn9); self._switch_nodes.append(sn9) #switch
        sn10=Switch(); self._g.add(sn10); self._switch_nodes.append(sn10) #switch


        #self._g.link((sn0,99),(n7,0)) #to the Internet
        self._g.link((sn0,0),(sn1,0))
        self._g.link((sn0,1),(sn2,0))
        self._g.link((sn0,2),(sn3,0))

        self._g.link((sn1,1),(n1,0))
        self._g.link((sn1,2),(sn3,1))

        self._g.link((sn2,1),(sn3,2))
        self._g.link((sn2,2),(n2,0))

        self._g.link((sn3,3),(fn1,1))
            
        self._g.link((fn1,2),(sn4,0))

        self._g.link((sn4,1),(sn5,0))
        self._g.link((sn4,2),(sn6,0))
        
        self._g.link((sn5,1),(sn7,0))
        
        self._g.link((sn5,2),(sn6,1))

        self._g.link((sn5,3),(n4,0))

        self._g.link((sn7,1),(n3,0))

        self._g.link((sn6,2),(fn2,0))

        self._g.link((fn2,1),(sn8,0))
        
        self._g.link((sn8,1),(sn9,0))
        self._g.link((sn8,2),(sn10,0))

        self._g.link((sn9,1),(sn10,1))
        self._g.link((sn9,2),(fn3,0))

        self._g.link((sn10,2),(n5,0))
        self._g.link((sn10,3),(n6,0))

        self._g.link((fn3,1),(n7,0))

        return

    def new_topology(self):
        #281635445620793
        #563110422331449
        #dpid1=1
        dpid1=563110422331449
        #n1=OF_Switch(48, 563110422331449); self._new_g.add(n1); self._of_switch_nodes.append(n1) #OF switch
        n1=OF_Switch(48, dpid1); self._new_g.add(n1); self._of_switch_nodes[dpid1]=n1 #OF switch
        #self._of_switch_nodes[0].add_entry(Entry(self._host_nodes[0]._default_gw, self._host_nodes[0]._ip_mask, 10))
        self._of_switch_nodes[dpid1].add_entry(Entry(self._host_nodes[0]._default_gw, self._host_nodes[0]._ip_mask, 10))
        self._host_nodes[0].set_dpid(dpid1)
        self._of_switch_nodes[dpid1].add_entry(Entry(self._host_nodes[1]._default_gw, self._host_nodes[1]._ip_mask, 2))
        self._host_nodes[1].set_dpid(dpid1)

        dpid2=2
        n2=OF_Switch(48, dpid2); self._new_g.add(n2); self._of_switch_nodes[dpid2]=n2 #OF switch 
        self._of_switch_nodes[dpid2].add_entry(Entry(self._host_nodes[4]._default_gw, self._host_nodes[4]._ip_mask, 1))
        self._host_nodes[4].set_dpid(dpid2)
        self._of_switch_nodes[dpid2].add_entry(Entry(self._host_nodes[6]._default_gw, self._host_nodes[6]._ip_mask, 2))
        self._host_nodes[6].set_dpid(dpid2)

        dpid3=3
        n3=OF_Switch(48, dpid3); self._new_g.add(n3); self._of_switch_nodes[dpid3]=n3 #OF switch
        self._of_switch_nodes[dpid3].add_entry(Entry(self._host_nodes[5]._default_gw, self._host_nodes[5]._ip_mask, 1))
        self._host_nodes[5].set_dpid(dpid3)

        dpid4=4
        n4=OF_Switch(8, dpid4); self._new_g.add(n4); self._of_switch_nodes[dpid4]=n4 #OF switch
        self._of_switch_nodes[dpid4].add_entry(Entry(self._host_nodes[3]._default_gw, self._host_nodes[3]._ip_mask, 1))
        self._host_nodes[3].set_dpid(dpid4)

        #dpid5=5
        dpid5=281635445620793
        #n5=OF_Switch(24, 281635445620793); self._new_g.add(n5); self._of_switch_nodes.append(n5) #OF switch
        #self._of_switch_nodes[4].add_entry(Entry(self._host_nodes[2]._default_gw, self._host_nodes[2]._ip_mask, 2))    
        #self._host_nodes[2].set_dpid(281635445620793)
        n5=OF_Switch(24, dpid5); self._new_g.add(n5); self._of_switch_nodes[dpid5]=n5 #OF switch
        self._of_switch_nodes[dpid5].add_entry(Entry(self._host_nodes[2]._default_gw, self._host_nodes[2]._ip_mask, 2))    
        self._host_nodes[2].set_dpid(dpid5)
        
        for i in xrange(len(self._host_nodes)): #add all previous host 
            self._new_g.add(self._host_nodes[i])
            
        #connect switches together to get a star
            
        self._new_g.link((n1,1),(n2,1)) #for switch 1
        self._new_g.link((n1,2),(n5,2)) 
        self._new_g.link((n1,3),(n4,3))
        self._new_g.link((n1,4),(n3,3))

        self._new_g.link((n2,2),(n3,1)) #for switch 2
        self._new_g.link((n2,3),(n4,4))
        self._new_g.link((n2,4),(n5,3))

        self._new_g.link((n3,2),(n4,1)) #for switch 3
        self._new_g.link((n3,4),(n5,4))

        self._new_g.link((n4,2),(n5,1)) #for switch 4

        
        #connect hosts to switches
        self._new_g.link((self._host_nodes[0],0),(n1,0))
        self._new_g.link((self._host_nodes[1],0),(n3,0))
        self._new_g.link((self._host_nodes[2],0),(n5,0))
        


    def is_internet_addr(self, addr):
        if (addr==[0,0,0,0]):
            return False
        for i in xrange(len(self._host_nodes)):
            if (self._host_nodes[i]._ip_addr!=[0,0,0,0]) and \
               (general_functions.addr_belongs_to_subnet \
                (self._host_nodes[i]._ip_addr, self._host_nodes[i]._ip_mask, addr)):
                #print "False"
                return False
        #print "True"
        return True

    def add_node_to_path(self, current_path, n):
        
        if (len(current_path)!=0):
            n2=current_path.pop()
            ports=self._g.find_port(n2[0], n)
            current_path.append([n2[0],ports[0]])

        current_path.append([n,0])
        return True


    def contains (self, current_path, n):
        for i in xrange(len(current_path)):
            if (n==current_path[i][0]):
                return True
        return False


    def delete_node_from_path(self, current_path):
        current_path.pop()
        return


    def find_all_paths (self, n1, n2, nodes_from_A_to_B, current_path=[], TTL=[0], done=[False], depth=[0]):
        self.add_node_to_path(current_path, n1)
        if (n1==n2):
            done[0]=True
            return 
        elif ((n1._label==2)&(TTL[0]!=0))|(TTL[0]==33):
            return
        elif (not done[0]):
            next_nodes=self._g.neighbors(n1)
            for i in next_nodes:
                if ((not self.contains(current_path, i))): # for all paths except previous -> split horizon
                    depth[0]+=1
                    TTL[0]+=1
                    self.find_all_paths( i, n2, nodes_from_A_to_B, current_path, TTL, done, depth)
                    TTL[0]-=1
                    depth[0]-=1
                    if (done[0]):
                        tmp=copy.deepcopy(current_path)
                        nodes_from_A_to_B.append(tmp)
                        done[0]=False
                    self.delete_node_from_path(current_path)
        return


    def rule_type(self, x):
        src_counter=0
        dst_counter=0
        for i in xrange(len(self._host_nodes)):
            if general_functions.addr_belongs_to_subnet(x.src_addr, x.src_mask, self._host_nodes[i]._ip_addr):
                src_counter+=1
            if general_functions.addr_belongs_to_subnet(x.dst_addr, x.dst_mask, self._host_nodes[i]._ip_addr):
                dst_counter+=1
        if (src_counter==1)and(dst_counter==1):
            if(x.action=="deny"):
                return 1
            else:
                return 2
        elif(src_counter>1)and(dst_counter==1):
            if (x.action=="deny"):
                return 3
            else:
                return 4
        elif(src_counter==1)and(dst_counter>1):
            if (x.action=="deny"):
                return 5
            else:
                return 6
        elif(src_counter>1)and(dst_counter>1):
            if (x.action=="deny"):
                return 7
            else:
                return 8
        

    def Sort(self, n1, n2, nodes_from_A_to_B):
       
        for i in xrange(len(nodes_from_A_to_B)):
            if (nodes_from_A_to_B[i][0]._label==3): #this is firewall
                nodes_from_A_to_B[i][0]._temp_rule_tree=copy.deepcopy(nodes_from_A_to_B[i][0]._rule_tree)
                for a in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree)):# perebor po proto
                    for b in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree[a])): # perebor po src_addr 
                        for c in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree[a][b])): # perebor po src_port
                            for d in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree[a][b][c])): # perebor po dst_addr
                                for e in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree[a][b][c][d])): # perebor po dst_port
                                    for f in xrange(len(nodes_from_A_to_B[i][0]._temp_rule_tree[a][b][c][d][e])): # perebor po number
                                        x=nodes_from_A_to_B[i][0]._temp_rule_tree[a][b][c][d][e][f]
                                        """
                                        if ((general_functions.addr_belongs_to_subnet(n1._ip_addr, n1._ip_mask, x.src_addr)or\
                                            general_functions.addr_belongs_to_subnet(x.src_addr, x.src_mask, n1._ip_addr))and\
                                            (general_functions.addr_belongs_to_subnet(n2._ip_addr, n2._ip_mask, x.dst_addr)or\
                                            general_functions.addr_belongs_to_subnet(x.dst_addr, x.dst_mask, n2._ip_addr))):
                                            rule_type=self.rule_type(x)
                                            if (rule_type!=1)and(rule_type!=2):
                                                temp_x=self.clarify_rule(rule_type)
                                        else:
                                            del nodes_from_A_to_B[i][0]._temp_rule_tree[a][b][c][d][e][f]


                                            
                                        """
                                        if ((self.is_internet_addr(x.dst_addr)) and (general_functions.addr_belongs_to_subnet\
                                                                                    (n1._ip_addr, n1._ip_mask, x.src_addr))) and\
                                                                                    (n1._ip_addr!=[0,0,0,0]):
                                            nodes_from_A_to_B[i][0]._rule_tree[a][b][c][d][e][f].was_used=True

                                        elif (self.is_internet_addr(x.src_addr)) and (not self.is_internet_addr(x.dst_addr)) and\
                                                                                     (n1._ip_addr==[0,0,0,0]):
                                            nodes_from_A_to_B[i][0]._rule_tree[a][b][c][d][e][f].was_used=True
                                            
                                        elif (x.src_addr==[0, 0, 0, 0]) and (general_functions.addr_belongs_to_subnet\
                                            (n1._ip_addr, n1._ip_mask, x.dst_addr)) and (n1._ip_addr!=[0,0,0,0]):

                                            nodes_from_A_to_B[i][0]._rule_tree[a][b][c][d][e][f].was_used=True #means matches this two nodes
                                        elif (n1._ip_addr!=[0,0,0,0])and((general_functions.addr_belongs_to_subnet(n1._ip_addr, n1._ip_mask, x.src_addr)) or\
                                           (general_functions.addr_belongs_to_subnet(x.src_addr, x.src_mask, n1._ip_addr))) and \
                                           ((general_functions.addr_belongs_to_subnet(n2._ip_addr, n2._ip_mask, x.dst_addr)) or\
                                           (general_functions.addr_belongs_to_subnet(x.dst_addr, x.dst_mask, n2._ip_addr))) and\
                                           (x.src_addr!=[0, 0, 0, 0]) or ((x.src_addr==[0, 0, 0, 0]) and (x.dst_addr==[0, 0, 0, 0])):
                                           #&(x.src_addr!=[0,0,0,0])&(x.dst_addr!=[0,0,0,0]):
                                            nodes_from_A_to_B[i][0]._rule_tree[a][b][c][d][e][f].was_used=True #means matches this two nodes
                                            #print "insert"
                                        else:
                                            #print "del"
                                            del nodes_from_A_to_B[i][0]._temp_rule_tree[a][b][c][d][e][f]
                                        

                #print "Temp_rule_tree=", general_functions.Tree_Print(nodes_from_A_to_B[i][0]._temp_rule_tree)

    

    def Redistribute_Rules(self, n1, n2, single_fw, number):
            
        if (n1._is_empty):
            #print "deepcopy"
            n1._new_rule_tree=copy.deepcopy(single_fw)
            n1._is_empty=False
            n1._current_number_of_rules=number
            return
        else:
            for a in xrange(len(single_fw)):# perebor po proto
                for b in xrange(len(single_fw[a])): # perebor po src_addr 
                    for c in xrange(len(single_fw[a][b])): # perebor po src_port
                        for d in xrange(len(single_fw[a][b][c])): # perebor po dst_addr
                            for e in xrange(len(single_fw[a][b][c][d])): # perebor po dst_port
                                for f in xrange(len(single_fw[a][b][c][d][e])):# perebor po number
                                    #print "insert"
                                    #single_fw[a][b][c][d][e][f].number=n1._current_number_of_rules
                                    #n1._current_number_of_rules+=1
                                    self.fw_manager.insert_rule_in_tree(n1._new_rule_tree, single_fw[a][b][c][d][e][f])
        


    def Analise(self, n1, n2):
        current_path=[]
        nodes_from_A_to_B=[]
        self.find_all_paths(n1, n2, nodes_from_A_to_B, current_path)

        for k in xrange(len(nodes_from_A_to_B)): #for each path
            single_fw=[[],[],[],[]]
            self.Sort(n1, n2, nodes_from_A_to_B[k])
            self.fw_manager.Build_Single_Firewall(nodes_from_A_to_B[k], single_fw)
            number=general_functions.Correct_Order(single_fw)
            self.Redistribute_Rules(n1, n2, single_fw, number)
            del single_fw
  
    def check_connection(self):

        #print "Host Nodes="
        #print self._host_nodes
        #print "Firewall Nodes="
        #print self._firewall_nodes

        for i in xrange(0, len(self._host_nodes), 1):
            for j in xrange(i+1, len(self._host_nodes), 1):
                self.Analise(self._host_nodes[i], self._host_nodes[j])
                self.Analise(self._host_nodes[j], self._host_nodes[i])
                #print "Host nodes", self._host_nodes[i], self._host_nodes[j] 
                #print "!@#$%^&*()!@#$%^&*(@#$%^&*(#$%^&YUIO@#$%^&*(0"
                #general_functions.Tree_Print(self._host_nodes[i]._new_rule_tree)
                #print "!@#$%^&*()!@#$%^&*(@#$%^&*(#$%^&YUIO@#$%^&*(0"

        for i in xrange(len(self._host_nodes)):
            general_functions.Correct_Order(self._host_nodes[i]._new_rule_tree)
            rule_list=[]
            rule_tree=[[],[],[],[]]
            general_functions.tree_to_list(self._host_nodes[i]._new_rule_tree, rule_list)
            self.fw_manager.tree_build(rule_list, rule_tree)
            del self._host_nodes[i]._new_rule_tree
            self._host_nodes[i]._new_rule_tree=copy.deepcopy(rule_tree)
            #print "Host Node Tree", self._host_nodes[i]._ip_addr
            #print "!@#$%^&*()!@#$%^&*(@#$%^&*(#$%^&YUIO@#$%^&*(0"
            #general_functions.Tree_Print(self._host_nodes[i]._new_rule_tree)
            #print "!@#$%^&*()!@#$%^&*(@#$%^&*(#$%^&YUIO@#$%^&*(0"

        #general_functions.Tree_Print(self._host_nodes[6]._new_rule_tree)



    def find_OF_switch(self, dpid):
        for i in xrange(len(self._of_switch_nodes)):
            if (self._of_switch_nodes[i].dpid==dpid):
                return i
        return -1


    def designate_rules_to_OF_switches(self):
        
        rule_list=[]
        rule_tree=[[],[],[],[]]

        dpid1=563110422331449
        self.fw_manager.parse("ext/TempSwitch1", rule_list)
        self.fw_manager.tree_build(rule_list, rule_tree)
        self._of_switch_nodes[dpid1].append_tree(rule_tree, self.fw_manager)
        del rule_list
        rule_list=[]
        del rule_tree
        rule_tree=[[],[],[],[]]
        self.fw_manager.parse("ext/TempSwitch2", rule_list)
        self.fw_manager.tree_build(rule_list, rule_tree)
        self._of_switch_nodes[2].append_tree(rule_tree, self.fw_manager)
        del rule_list
        rule_list=[]
        del rule_tree
        rule_tree=[[],[],[],[]]
        self.fw_manager.parse("ext/TempSwitch3", rule_list)
        self.fw_manager.tree_build(rule_list, rule_tree)
        self._of_switch_nodes[3].append_tree(rule_tree, self.fw_manager)
        del rule_list
        rule_list=[]
        del rule_tree
        rule_tree=[[],[],[],[]]
        self.fw_manager.parse("ext/TempSwitch4", rule_list)
        self.fw_manager.tree_build(rule_list, rule_tree)
        self._of_switch_nodes[4].append_tree(rule_tree, self.fw_manager)
        del rule_list
        rule_list=[]
        del rule_tree
        rule_tree=[[],[],[],[]]

        dpid5=281635445620793
        self.fw_manager.parse("ext/TempSwitch5", rule_list)
        self.fw_manager.tree_build(rule_list, rule_tree)
        self._of_switch_nodes[dpid5].append_tree(rule_tree, self.fw_manager)
        
        """
        for i in (xrange(len(self._host_nodes))):
            index=self.find_OF_switch(self._host_nodes[i].dpid)
            if (index==-1):
                continue
            self._of_switch_nodes[index].append_tree(self._host_nodes[i]._new_rule_tree, self.fw_manager)

        for i in xrange(len(self._of_switch_nodes)):
            print "*******************************************", self._of_switch_nodes[i].dpid
            general_functions.Tree_Print(self._of_switch_nodes[i].rule_tree)
            #for j in xrange(len(self._of_switch_nodes[i].entry_list)):
            #    print self._of_switch_nodes[i].entry_list[j].ip_addr
            #    print self._of_switch_nodes[i].entry_list[j].ip_mask
        """


            
                                        
#reload(graph)
#reload(fw_policy)
#reload (general_functions)
#Topo=Topology()
#print "QWERTY"
#print "??????????????????????????????????????????????"
#Topo.check_connection()
#Topo.new_topology()
#Topo.designate_rules_to_OF_switches()



