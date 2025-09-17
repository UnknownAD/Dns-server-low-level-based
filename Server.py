
#!/usr/bin/python3
import socket
from threading import Thread
import time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("0.0.0.0",9999))
clients=[]
DNS_AUTHORITATIVE_SERVERS=[]
dns_db=[{"name":  'google.com',"ip":"190.89.55.23"}]
class opcode:
      def __init__(self,opcode):
          pass
      #update and notify and status functions
      #we need to inherit so that we get the opcode from the object
class Client:

      def __init__(self,c,data):
         self.packet=data
         self.socketobject=c
         self.qtype=format(0,"04b")

      def get_tid(self):
         self.tid=data[:2]
         tid=int.from_bytes(data[:2])
         tid=tid
         return '[+] transaction id : {}'.format(tid)
         
         
      def get_domain_name(self):
             domains=[]
             i = 12
             labels = []
             dns=""
             while data[i] != 0:
                length = data[i]
                i += 1
                label = self.packet[i:i+length].decode()
                labels.append(label)
                i += length
                self.dns_hex_format=data[12:i]
                #print(labels)
             for n,p in enumerate(labels):
                 
                 if n==len(labels)-1:
                        dns=dns+p
                 else:
                     dns=dns+p+"."
             domains.append(dns)
             self.domain_names=domains
             i+=1 #to escape the dname pointer
             self.QTYPE=data[i:i+2]
             print("QTYPE: ",end="\x20")
             print(self.QTYPE)
             self.QCLASS=b"\x00\x01"
             self.length=i
             return domains
#b'\x06google\x03com\x03'
          
          
      def get_flags(self):
         QQ="1" #Sands for responce
         flags = self.packet [2:4]
         self.flags=flags
         binary_seq=format(int.from_bytes(flags),"016b")
         self.binary_seq=binary_seq
         
         if binary_seq[0]!="0":
            print("[+] Bad request format",end="")
            print("At the QQ header : a query was expected but a responce were indicated")
            print(binary_seq)
            remove_client(self)
         opcode= binary_seq[1:5]

         if opcode == self.qtype:
            print("[+] Standard query detected")

         else:
            print(binary_seq)
            print(f"opcode: {opcode}")
            remove_client(self)
         AA='0'    #Default value for Authoritative answers
         TC= int.from_bytes(flags)>>9 &0b1 #TC=int(binary_seq) >>15
         TC=str(TC)
         RA='0' #Default value for Testing
         self.recursion_desired=binary_seq[7:8]
         recursion_available="0"
         self.RA=recursion(self)
         if self.RA:
             recursion_available="1"#get recursion result
         else:
             pass
         ZONE=binary_seq[9:12]
         RCODE = "0000" #No Error
         self.str_flags=QQ+opcode+AA+TC+self.recursion_desired+recursion_available+ZONE+RCODE
         
         
         
      def second_portion(self):
         self.get_answers()
         qcount=self.packet[4:6]
         self.NSCOUNT=0
       #  self.ANCOUNT=2
         return qcount+self.ANCOUNT.to_bytes(2)+self.NSCOUNT.to_bytes(2)+int(0).to_bytes(2)
          
      def build_responce(self):
         #check if there is recursion
         #check how many queries are sent
         raw_str=self.get_flags()
         return raw_str
         
         
      def get_answers(self):
          global dns_db
          self.ANCOUNT=0
          self.answers={}
          for Qn in self.domain_names:
              for item in dns_db:
                  if item["name"]==Qn:
                      self.answers[item["name"]]=item["ip"]
                      self.ANCOUNT+=1
          return self.answers
          
          
      def build_answer_section(self):
          answer_section=b""
          for ix in (self.domain_names):
             POINTER=b"\xc0\x0c"
             RDATA=socket.inet_aton(self.answers[ix])
             #Expect multiple ip adresses
         #type and class are already defined
             DATA_LENGTH=len(RDATA).to_bytes(2)
             TTL=b"\x00\x00\x01\x0c"
             answer_section+=POINTER+self.QTYPE+self.QCLASS+TTL+DATA_LENGTH+RDATA
            
             return answer_section
      
      
      def rebuild_flags(self):
          print("[+] Generating the responce..")
        #print(self.binary_seq)
          F=eval("0b"+self.str_flags)
        #print(f"flags decimal value: {F}")
          return int(F).to_bytes(2,"big")
          
          
def recursion(self):
      return False

data,addr=s.recvfrom(512)
new_client=Client(addr,data)
clients.append(new_client)
print(new_client.get_tid())
t= f"[+] {time.gmtime()[0]},{time.gmtime()[1]},{time.gmtime()[2]}th | {time.gmtime()[3]}:{time.gmtime()[4]}"
print(t)
flags=new_client.get_flags()
new_client.get_domain_name()
new_client.second_p=new_client.second_portion()
print("[+] Responce: \n")
new_client.built_flags=new_client.rebuild_flags()
final_responce=new_client.tid+new_client.built_flags+new_client.second_p+new_client.dns_hex_format+b"\x00"+new_client.QTYPE+new_client.QCLASS+new_client.build_answer_section()
print(final_responce)
second_answer = (
    b"\xc0\x0c"              # NAME (pointer to question name at offset 0x0c)
    + b"\x00\x01"            # TYPE = A
    + b"\x00\x01"            # CLASS = IN
    + b"\x00\x00\x00\x3c"    # TTL = 60 seconds
    + b"\x00\x04"            # RDLENGTH = 4
    + b"\xc0\xa8\x00\x01"    # RDATA = 192.168.0.1
)
print("________________")
s.sendto(final_responce+second_answer,addr)
