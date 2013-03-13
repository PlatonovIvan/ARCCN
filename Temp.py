import sys

class Addr():
    subnets=["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]

    def ip_addr_to_list(self, addr):
        temp=addr.split("/")
        ip_addr=temp[0].split(".")
        for i in xrange(len(ip_addr)):
            ip_addr[i]=int(ip_addr[i])
        return ip_addr

    def mask_to_list(self, addr):
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
        
      

    def addr_belongs_to_subnet(self, addr):
        ip_addr=self.ip_addr_to_list(addr)
        for i in xrange(len(self.subnets)):
            subnet_addr=self.ip_addr_to_list(self.subnets[i])
            subnet_mask=self.mask_to_list(self.subnets[i])
            flag=True
            for j in xrange(0,4):
                if ((subnet_addr[j])!=(ip_addr[j])&(subnet_mask[j])):
                    flag=False
            if flag:
                return i
        return -1



addr=Addr()
print addr.addr_belongs_to_subnet("10.0.1.23")
