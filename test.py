'''
Author: p0p1ng
Date: 2023-10-26 12:39:53
LastEditTime: 2023-10-26 13:43:05
Description: 
FilePath: /Lab1-Sniffer/test.py
'''
import hexdump
import pcap
import dpkt

pc = pcap.pcap("en0", timeout_ms=50, timestamp_in_ns=False)
for timestamp, pkt in pc:
    hex_rep = hexdump.hexdump(pkt, result='return')
    decode = {
            pcap.DLT_LOOP: dpkt.loopback.Loopback,
            pcap.DLT_NULL: dpkt.loopback.Loopback,
            pcap.DLT_EN10MB: dpkt.ethernet.Ethernet
        }[pc.datalink()]
    ethernet_pkt = decode(pkt)
    if ethernet_pkt.type == 0x800:
        ip = ethernet_pkt.data
    else:
        continue
    if isinstance(ip.data, dpkt.tcp.TCP):
        tcp = ip.data
        src_port = str(tcp.sport)
        dst_port = str(tcp.dport)
        
        try:
            request = dpkt.http.Request(tcp.data)
            print(request)
            request_list = []
            method = request.method
            uri = request.uri
            ver = str(request.version)
            request_list = ['method: '+method, 'uri: '+uri, 'version: '+ver]
            for i in request.headers:
                request_list.append(i + ": " + request.headers[i])
            print(src_port, dst_port)
            body = request.body.decode("utf8", "ignore")
            data = request.data.decode("utf8", "ignore")
            request_list.append("body: "+ body)
            request_list.append("data: "+ data)
            print(request_list)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError):
            #print("Invalid HTTP request")
            continue
