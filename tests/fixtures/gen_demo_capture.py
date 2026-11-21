#!/usr/bin/env python3
"""Writes a fictional home-network capture (tests/fixtures/demo.pcap) used for the README screenshots.

Every host is invented: a laptop, a TV, a phone and a NAS on 192.168.1.0/24 talk to well-known public
services, and three fictional behaviours show in Insights: a visitor scanning the NAS, a phone calling
a TEST-NET address at a steady rhythm, and DNS names that are suspiciously long.

Usage: gen_demo_capture.py tests/fixtures/demo.pcap
"""
import struct, random, socket, sys
random.seed(7)
pk=[]  # (time, bytes)
def mac(s):return bytes(int(x,16) for x in s.split(':'))
M={'me':mac('3c:22:fb:7a:10:01'),'gw':mac('f0:9f:c2:00:aa:01'),'tv':mac('b8:27:eb:44:19:02'),'nas':mac('00:11:32:5c:de:03'),'ph':mac('a4:83:e7:91:20:04')}
IP={'me':'192.168.1.23','gw':'192.168.1.1','tv':'192.168.1.40','nas':'192.168.1.60','ph':'192.168.1.31'}
def ck(b):
    if len(b)%2:b+=b'\0'
    s=sum(struct.unpack('!%dH'%(len(b)//2),b));s=(s>>16)+(s&0xffff);s+=s>>16;return ~s&0xffff
ipid=[1]
def ip(src,dst,proto,payload,ttl=64):
    ipid[0]+=1
    h=struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(payload),ipid[0],0x4000,ttl,proto,0,socket.inet_aton(src),socket.inet_aton(dst))
    h=h[:10]+struct.pack('!H',ck(h))+h[12:];return h+payload
def tcp(sp,dp,seq,ack,fl,data=b'',win=64240):
    return struct.pack('!HHIIBBHHH',sp,dp,seq&0xffffffff,ack&0xffffffff,5<<4,fl,win,0,0)+data
def udp(sp,dp,data):return struct.pack('!HHHH',sp,dp,8+len(data),0)+data
t=[0.0]
def emit(dt,srcn,dstn,proto,payload,ttl=64):
    t[0]+=dt
    sm,si=(M[srcn],IP[srcn]) if srcn in M else (M['gw'],srcn)
    dm,di=(M[dstn],IP[dstn]) if dstn in M else (M['gw'],dstn)
    if srcn not in M and dstn not in M:raise
    pk.append((t[0],dm+sm+struct.pack('!H',0x0800)+ip(si,di,proto,payload,ttl)))
def name(n):return b''.join(bytes([len(x)])+x.encode() for x in n.split('.'))+b'\0'
def dns(q,id,ans=None,qt=1):
    h=struct.pack('!HHHHHH',id,0x8180 if ans else 0x0100,1,1 if ans else 0,0,0)
    r=h+name(q)+struct.pack('!HH',qt,1)
    if ans:r+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,300,4)+socket.inet_aton(ans)
    return r
def do_dns(client,q,ans,dt=0.4):
    i=random.randint(1000,60000);sp=random.randint(40000,60000)
    emit(dt,client,'gw',17,udp(sp,53,dns(q,i)))
    emit(0.012+random.random()*0.02,'gw',client,17,udp(53,sp,dns(q,i,ans)))
def hello(sni):
    s=sni.encode();ext=struct.pack('!HHHBH',0,len(s)+5,len(s)+3,0,len(s))+s
    ext+=struct.pack('!HHH',0x0010,0x000e,0x000c)+b'\x02h2\x08http/1.1'
    ext+=struct.pack('!HHH',0x002b,3,0)[:4]+b'\x02\x03\x04'
    ch=b'\x03\x03'+bytes(random.getrandbits(8) for _ in range(32))+b'\x20'+bytes(32)+struct.pack('!H',4)+b'\x13\x01\x13\x02'+b'\x01\x00'+struct.pack('!H',len(ext))+ext
    hs=b'\x01'+struct.pack('!I',len(ch))[1:]+ch
    return b'\x16\x03\x01'+struct.pack('!H',len(hs))+hs
def flow(client,server,port,start,reqs,resps,mss=1448,rtt=0.03):
    sp=random.randint(41000,60000);cs=random.randint(1,2**31);ss=random.randint(1,2**31)
    emit(start,client,server,6,tcp(sp,port,cs,0,0x02))
    emit(rtt,server,client,6,tcp(port,sp,ss,cs+1,0x12));cs+=1;ss+=1
    emit(0.001,client,server,6,tcp(sp,port,cs,ss,0x10))
    for req in reqs:
        emit(0.004,client,server,6,tcp(sp,port,cs,ss,0x18,req));cs+=len(req)
        emit(rtt,server,client,6,tcp(port,sp,ss,cs,0x10))
    for body in resps:
        off=0
        while off<len(body):
            ch=body[off:off+mss];off+=len(ch)
            emit(0.0006+random.random()*0.0008,server,client,6,tcp(port,sp,ss,cs,0x18,ch));ss+=len(ch)
            if (off//mss)%2==0:emit(0.0002,client,server,6,tcp(sp,port,cs,ss,0x10))
        emit(0.002,client,server,6,tcp(sp,port,cs,ss,0x10))
    emit(0.01,client,server,6,tcp(sp,port,cs,ss,0x11));cs+=1
    emit(rtt,server,client,6,tcp(port,sp,ss,cs,0x11));ss+=1
    emit(0.001,client,server,6,tcp(sp,port,cs,ss,0x10))
def tls(client,server,sni,start,kb,port=443):
    app=lambda n:b'\x17\x03\x03'+struct.pack('!H',n)+bytes(random.getrandbits(8) for _ in range(n))
    sh=b'\x16\x03\x03'+struct.pack('!H',90)+b'\x02\x00\x00\x56\x03\x03'+bytes(random.getrandbits(8) for _ in range(32))+b'\x20'+bytes(32)+b'\x13\x01\x00\x00\x00'
    sh=sh+bytes(90-(len(sh)-5))
    body=b''.join(app(1400) for _ in range(max(1,kb*1000//1400)))
    flow(client,server,port,start,[hello(sni),app(80)],[sh+app(1200),body],rtt=0.02+random.random()*0.05)
def http(client,server,path,host,ctype,body,start):
    req=('GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\nAccept: */*\r\n\r\n'%(path,host)).encode()
    resp=('HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Type: %s\r\nContent-Length: %d\r\nCache-Control: max-age=3600\r\n\r\n'%(ctype,len(body))).encode()+body
    flow(client,server,80,start,[req],[resp],rtt=0.025)
def arp(op,src,dst):
    sm,si=M[src],IP[src];dm=M[dst] if op==2 else b'\0'*6
    p=struct.pack('!HHBBH',1,0x0800,6,4,op)+sm+socket.inet_aton(si)+dm+socket.inet_aton(IP[dst])
    t[0]+=0.05;pk.append((t[0],(M[dst] if op==2 else b'\xff'*6)+sm+b'\x08\x06'+p))
def icmp(a,b,seq,reply,dt=1.0):
    d=struct.pack('!BBHHH',0 if reply else 8,0,0,0x2a1b,seq)+bytes(range(48))
    d=d[:2]+struct.pack('!H',ck(d))+d[4:];emit(dt,a,b,1,d)
def mdns(src,q):
    t[0]+=0.6;p=udp(5353,5353,struct.pack('!HHHHHH',0,0,1,0,0,0)+name(q)+struct.pack('!HH',12,1))
    pk.append((t[0],b'\x01\x00\x5e\x00\x00\xfb'+M[src]+b'\x08\x00'+ip(IP[src],'224.0.0.251',17,p,255)))
random.seed(7)
arp(1,'me','gw');arp(2,'gw','me')
for s in range(1,4):icmp('me','gw',s,False,0.3);icmp('gw','me',s,True,0.004)
S={'github':'140.82.121.4','jsd':'104.16.85.20','proton':'185.70.42.37','wiki':'185.15.58.224','yt':'142.250.179.110','ex':'93.184.216.34','api':'151.101.1.140','cf':'1.1.1.1','mirror':'195.135.221.134'}
for q,a in [('github.com',S['github']),('cdn.jsdelivr.net',S['jsd']),('mail.proton.me',S['proton']),('en.wikipedia.org',S['wiki']),('www.youtube.com',S['yt']),('example.org',S['ex']),('api.fastly.com',S['api']),('mirror.rackspace.com',S['mirror'])]:
    do_dns('me',q,a,0.25)
mdns('tv','_googlecast._tcp.local');mdns('ph','_airplay._tcp.local');mdns('nas','_smb._tcp.local')
tls('me',S['github'],'github.com',0.2,60)
tls('me',S['jsd'],'cdn.jsdelivr.net',0.1,60)
tls('me',S['proton'],'mail.proton.me',0.2,40)
html=b'<!doctype html><html><head><title>Example Domain</title></head><body><h1>Example Domain</h1><p>This domain is for use in illustrative examples.</p></body></html>'
http('me',S['ex'],'/','example.org','text/html',html,0.3)
http('me',S['api'],'/v1/status.json','api.fastly.com','application/json',b'{"status":"ok","regions":["eu-west","us-east","ap-south"],"latency_ms":14}',0.5)
http('me',S['mirror'],'/archlinux/core/os/x86_64/core.db','mirror.rackspace.com','application/octet-stream',bytes(random.getrandbits(8) for _ in range(250000)),0.4)
tls('me',S['wiki'],'en.wikipedia.org',0.6,90)
tls('me',S['yt'],'www.youtube.com',0.5,350)
tls('tv',S['yt'],'rr3---sn-ab5l6n7y.googlevideo.com',1.2,200)
for q,a in [('time.cloudflare.com',S['cf']),('connectivitycheck.gstatic.com','142.250.179.99')]:do_dns('tv',q,a,0.3)
tls('ph',S['proton'],'push.proton.me',0.8,25)
# NAS SMB-ish LAN traffic
flow('me','nas',445,0.5,[b'\xfeSMB'+bytes(60)],[bytes(random.getrandbits(8) for _ in range(120000))],mss=1448,rtt=0.002)
# retransmission burst
emit(0.5,'me',S['api'],6,tcp(50000,443,1000,1,0x18,b'x'*100))
for _ in range(3):emit(0.2*(2**_),'me',S['api'],6,tcp(50000,443,1000,1,0x18,b'x'*100))
# a port-scan like burst from an unknown LAN host? keep calm: failed connections
for p in (22,23,3389):
    emit(0.2,'ph','nas',6,tcp(51000+p,p,5000,0,0x02));emit(0.001,'nas','ph',6,tcp(p,51000+p,0,5001,0x14))
# --- fictional behaviours shown by Insights ---
M['visitor'] = mac('9c:b6:d0:12:34:56')
IP['visitor'] = '192.168.1.77'
BEACON = '203.0.113.50'  # TEST-NET-3: documentation range, never routed


def emit_at(when, srcn, dstn, proto, payload):
    """Like emit, at an absolute time instead of after the previous packet."""
    sm, si = (M[srcn], IP[srcn]) if srcn in M else (M['gw'], srcn)
    dm, di = (M[dstn], IP[dstn]) if dstn in M else (M['gw'], dstn)
    pk.append((when, dm + sm + struct.pack('!H', 0x0800) + ip(si, di, proto, payload)))


# A visitor probes 30 ports of the NAS; the closed ones answer with a reset.
for i, p in enumerate(range(20, 50)):
    when = 6.0 + i * 0.02
    emit_at(when, 'visitor', 'nas', 6, tcp(40000 + i, p, 7000 + i, 0, 0x02))
    emit_at(when + 0.001, 'nas', 'visitor', 6, tcp(p, 40000 + i, 0, 7001 + i, 0x14))

# The phone calls the same address every 1.4 s (4.2 s once the capture is stretched).
for i in range(10):
    when = 2.0 + i * 1.4
    sport, seq = 52000 + i, 9000 + i
    emit_at(when, 'ph', BEACON, 6, tcp(sport, 443, seq, 0, 0x02))
    emit_at(when + 0.04, BEACON, 'ph', 6, tcp(443, sport, 3000, seq + 1, 0x12))
    emit_at(when + 0.041, 'ph', BEACON, 6, tcp(sport, 443, seq + 1, 3001, 0x10))

# Very long DNS names, as a tunnel or a generated domain would ask for.
for i in range(6):
    label = ''.join(random.choice('0123456789abcdef') for _ in range(48))
    t[0] = 7.0 + i * 0.3
    do_dns('ph', f'{label}.t.example.net', '203.0.113.9', 0.0)

pk.sort(key=lambda x: x[0])
with open(sys.argv[1], 'wb') as f:
    f.write(struct.pack('<IHHiIII', 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
    base = 1763650000
    for ts, b in ((x * 3, y) for x, y in pk):
        f.write(struct.pack('<IIII', base + int(ts), int((ts % 1) * 1e6), len(b), len(b)))
        f.write(b)
print(len(pk), 'packets', round(pk[-1][0] * 3, 1), 's')
