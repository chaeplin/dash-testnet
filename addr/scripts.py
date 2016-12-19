#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from lib.script import *

def script_forma_5():                                      
    script_hex = '76a914fd85adfcf0c5c6a3f671428a7bfa3944cb84030588ac'
    print('yjRwwxf95GtmK41oEH9VDPdDCtV1Jczmip', script_to_addr(script_hex), len(bytes.fromhex(script_hex)))

def script_forma_1(): 
    script_hex = '41047559d13c3f81b1fadbd8dd03e4b5a1c73b05e2b980e00d467aa9440b29c7de23664dde6428d75cafed22ae4f0d302e26c5c5a5dd4d3e1b796d7281bdc9430f35ac'
    print('yb21342iADyqAotjwcn4imqjvAcdYhnzeH', script_to_addr(script_hex), len(bytes.fromhex(script_hex)))

def script_forma_2(): 
    script_hex = '047559d13c3f81b1fadbd8dd03e4b5a1c73b05e2b980e00d467aa9440b29c7de23664dde6428d75cafed22ae4f0d302e26c5c5a5dd4d3e1b796d7281bdc9430f35ac'
    print('yb21342iADyqAotjwcn4imqjvAcdYhnzeH', script_to_addr(script_hex), len(bytes.fromhex(script_hex)))

def script_forma_3():
    script_hex = '76a914fd85adfcf0c5c6a3f671428a7bfa3944cb84030588acacaa'
    print('yjRwwxf95GtmK41oEH9VDPdDCtV1Jczmip', script_to_addr(script_hex), len(bytes.fromhex(script_hex)))

def script_forma_4():                                       
    script_hex = '76a90088ac'
    print('unspendable', script_to_addr(script_hex), len(bytes.fromhex(script_hex)))

def script_p2p():
    script_hex = '6a281adb1bf4cef81ede4a63ad5ca5943e5288fffc210d90a861a60a96658d7f90580000000000000000'
    print('nulldata', script_to_addr(script_hex))

def script_compressed():
    script_hex = '2103717f7082f58395f02afb45b1ae871cae31293b33c64c8d9568d9cac09fa70c51ac'
    print('yhF732jM8hA2e5svfBCa1heFbdHVNXdM8n', script_to_addr(script_hex), len(bytes.fromhex(script_hex)))    

# check

script_forma_5()
script_forma_1()
script_forma_2()
script_forma_3()
script_forma_4()
script_p2p()
script_compressed()

