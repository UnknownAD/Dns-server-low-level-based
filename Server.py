#!/usr/bin/python3
import socket
from threading import Thread
import time
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.bind(("0.0.0.0",9999))
clients=[]
DNS_AUTHORITATIVE_SERVERS=[{"host":"0.0.0.0","port":8888}]
dns_db=[
      {"name":  'google.com',
      "ip":{
      "190.89.55.23","8.8.4.4","9.8.9.8"
          } 
      },{"name": "djilali.com","ip":{"127.0.0.1"}}
   ]
class opcode:
    pass
class Client:
      
      def __init__(self,c,data):
         self.packet=data
         self.socketobject=c
         self.qtype=format(0,"04b")
         self.answer_exists=False
         self.ANCOUNT=0
         
      def get_tid(self):
         self.tid=self.packet[:2]
         tid=int.from_bytes(self.packet[:2])
         return '[+] transaction id : {}'.format(tid)
         
      def get_domain_name(self):
             domains=[]
             i = 12
             labels = []
             dns=""
             while self.packet[i] != 0:
                length = self.packet[i]
                i += 1
                label = self.packet[i:i+length].decode()
                labels.append(label)
                i += length
                self.dns_hex_format=self.packet[12:i]
                #print(labels)
             for n,p in enumerate(labels):
                 
                 if n==len(labels)-1:
                        dns=dns+p
                 else:
                     dns=dns+p+"."
             domains.append(dns)
             self.domain_names=domains
             i+=1 #to escape the dname pointer
             self.QTYPE=self.packet[i:i+2]
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
         self.RA="0"
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
        
         self.second_p= qcount+self.ANCOUNT.to_bytes(2)+self.NSCOUNT.to_bytes(2)+int(0).to_bytes(2)
         return self.second_p
         
         
      def build_responce(self):
         #check if there is recursion
         #check how many queries are sent
         raw_str=self.get_flags()
         
         return raw_str
         
         
      def get_answers(self):
          global dns_db
          self.ANCOUNT=0
          self.answers={}
          self.answer_exists=False
          for Qn in self.domain_names:
              for item in dns_db:        
                  print(f"[+] Checking item: {item}")
                  if item["name"]==Qn:
                      self.answers[item["name"]]={}
                      for apn,a in enumerate(item["ip"]):
                         self.answers[item["name"]].__setitem__(apn,a)
                         if apn>0:
                             self.answer_exists=True
                             self.ANCOUNT=len(item["ip"])
                      print(self.answers)
          if not self.answer_exists:
                   return b""
          if self.answer_exists:
                   return self.answers
      def build_answer_section(self):
          answer_section=b""
          #print(f"[+] Domain names {self.domain_names}")
          d=self.domain_names[0]
          for ix in (self.domain_names[0]):
             POINTER=b"\xc0\x0c"
             if self.answer_exists:
                 #print(self.answers[d])
                 for answer_index in self.answers[d]:
                    newip=self.answers[d].__getitem__(answer_index)
                    RDATA=socket.inet_aton(newip)
                    DATA_LENGTH=len(RDATA).to_bytes(2)
                    TTL=b"\x00\x00\x01\x0c"
                    answer_section+=POINTER+self.QTYPE+self.QCLASS+TTL+DATA_LENGTH+RDATA
                 return answer_section
             else:
                 print("recursion is done")
                 RP=recursion(d)
                 print(RP)
                 POINTER=b"\xc0\x0c"
                 recursive_answer=b""
                 self.ANCOUNT=len(RP).to_bytes(2)
                 if len(RP)>0:
                    # self.ANCOUNT=len(RP)
                     self.answer_exists=True
                     for RRE in RP:
                         print(RRE)
                         RDATA=socket.inet_aton(RRE)
                         recursive_answer+=POINTER+self.QTYPE+self.QCLASS+b"\x00\x00\xc0\xc0"+len(RDATA).to_bytes(2)+RDATA
                     self.second_p=self.packet[4:6]+self.ANCOUNT+self.NSCOUNT.to_bytes(2)+int(0).to_bytes(2)
                     
                   
                 return recursive_answer
                         
                         
              #   return answer_section
      def rebuild_flags(self):
          print("[+] Generating the responce..")
          F=eval("0b"+self.str_flags)
          return int(F).to_bytes(2,"big")
          
def recursion(domain):
      global DNS_AUTHORITATIVE_SERVERS
      TID=b"\x49\x20"
      QQ=0
      OPCODE=0
      AA=0
      RD=1
      RA=0
      ZONE=0
      RCODE=0
      QDCOUNT=b"\x00\x01"
      ANCOUNT=b"\x00\x00"
      NSCOUNT=b"\x00\x00"
      ARCOUNT=b"\x00\x00"
      domain_parts=domain.split(".")
      raw_bytes_dname=b""
      # example ["www","google","com"]
      for part in domain_parts:
          raw_bytes_dname+=(len(part)).to_bytes(1)+part.encode()
      raw_bytes_dname+=b"\x00"
      QTYPE=b"\x00\x01"
      QCLASS=b"\x00\x01"
      flags=QQ<<15 |  OPCODE<<11  |AA <<10 | 0 <<9 |RD <<8 | RA <<7 | ZONE <<4 | RCODE
      query=TID+flags.to_bytes(2,"big")+QDCOUNT+ANCOUNT+NSCOUNT+ARCOUNT+raw_bytes_dname+QTYPE+QCLASS
     
      for AUTH in DNS_AUTHORITATIVE_SERVERS:
         
          rec=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
          try:
             rec.connect((AUTH["host"],AUTH["port"]))
        
             rec.send(query)
          except Exception as error:
              print("[!] Failed to reach authoritative server")
              return Null
              
          responce= rec.recvfrom(512)[0]
          ancount=int.from_bytes(responce[6:8])
          print(f"number of answers from recursion :{ancount}")
          re=[]
          index=28+len(raw_bytes_dname)
          print(responce[index:4+index])
          shift=16
          rec.close()
          n=0
          for x in range(ancount):
                  n=x
                  if x==0:
                      n=x+1
                  re.append(socket.inet_ntoa(responce[index:index+4]))
                  index=shift*n+index
          return re
def handler(data,addr):
     global s
     print(data)
     new_client=Client(addr,data)
     print(addr)
     clients.append(new_client)
     print(new_client.get_tid())
     t= f"[+] {time.gmtime()[0]},{time.gmtime()[1]},{time.gmtime()[2]}th | {time.gmtime()[3]}:{time.gmtime()[4]}"
     print(t)
     flags=new_client.get_flags()
     new_client.get_domain_name()
     new_client.second_p=new_client.second_portion()
     answer_section=new_client.build_answer_section()
     new_client.built_flags=new_client.rebuild_flags()
     final_responce=new_client.tid+new_client.built_flags+new_client.second_p+new_client.dns_hex_format+b"\x00"+new_client.QTYPE+new_client.QCLASS+answer_section
     print(f"[+] Number of answers : {new_client.ANCOUNT}")
     s.sendto(final_responce,addr)
def listening():
    global s
    while True:
       data,addr=s.recvfrom(512)
       t2=Thread(target=handler,args=(data,addr))
       t2.start()
listening()