#!/usr/bin/env python
#coding=utf-8
"""
author:0c0c0f
time:2015-10-30
"""
from libmproxy import controller, proxy
from libmproxy.models import decoded
import AutoSqli
import re
import os
import pdb
import sys
reload(sys)
sys.setdefaultencoding('utf8')

class StickyMaster(controller.Master):
    def __init__(self, server):
        controller.Master.__init__(self, server)
        self.stickyhosts = {}
    def run(self):
        try:
            return controller.Master.run(self)
        except KeyboardInterrupt:
            self.shutdown()
 
    def findword(self,flow):
        stringword1 = 'passwd'
        stringword2 = 'password'
        content = flow.request.content
        querystring = flow.request.get_query()
        #在url参数中查找
        for eachp in querystring:
            if eachp[1].find(stringword1) != -1 or eachp[1].find(stringword2) != -1:
                return 1
        #在content中寻找
        if content.find(stringword1) != -1 or content.find(stringword2) != -1:
            return 1
        return 0
    def sqlmap(self,flow):
        #send url to sqlmap                                                                                                                                                        
        print("send request: %s%s to sqlmapapi.py" % (flow.request.host, flow.request.path))                                                                                       
        url = "http//:%s%s" % (flow.request.host, flow.request.path)                                                                                                               
        t = AutoSqli('http://127.0.0.1:8775',url)                                                                                                                                  
        t.run()                                         
    def orderLeak(self,flow):
        return 1
    def InfoLeak(self,flow):
        re_info = re.compile('^0\d{2,3}\d{7,8}$|^1[358]\d{9}$|^147\d{8}',re.IGNORECASE | re.DOTALL | re.MULTILINE)
        #re_info = re.compile('0\d{2,3}\d{7,8}|1[358]\d{9}|147\d{8}',re.IGNORECASE | re.DOTALL | re.MULTILINE)
        #re_info = re.compile('1[358]\d{9}|147\d{8}',re.IGNORECASE | re.DOTALL | re.MULTILINE)
        #re_info = re.compile('1[3578]\d{9}',re.IGNORECASE | re.DOTALL | re.MULTILINE)
        #re_info = re.compile('15568816981',re.IGNORECASE | re.DOTALL | re.MULTILINE)
        if flow.request.pretty_host.endswith("ctrip.com"):
            result  = re_info.findall(flow.response.content)
            if len(result) == 0:
                return 0
            else:
                print result
            return 1
    def log(sef,uri):
        return 1
    def handle_request(self, flow):
        flag = self.findword(flow)
        if flag == 1:
            str = flow.request.get_query()
            con = flow.request.content
            url = flow.request.path
            m = flow.request.method
            print 'method:' + m
            print '\n'
            print 'query:\n'
            for eachp in str:
                print eachp[0] + '=' + eachp[1]
                print '\n'
            print '\n'
            print 'url:' + url
            print '\n'
            print 'content:' + con
            print '------------------\n'
        flow.reply()        
    def handle_response(self, flow):
        with decoded(flow.response):  # automatically decode gzipped responses.
            try:
	        flag = self.InfoLeak(flow)
                if flag == 1:
                    print("handle request: %s%s" % (flow.request.host, flow.request.path))
            except Exception,ex:  # Unknown image types etc.
                print Exception,":",ex
        flow.reply() 

config = proxy.ProxyConfig(
    #cacert = os.path.expanduser("~/.mitmproxy/mitmproxy-ca.pem")
)
server = proxy.ProxyServer(config)
m = StickyMaster(server)
m.run()
