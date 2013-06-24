# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

from waflib import Build, Logs, Utils, Task, TaskGen, Configure;

def options(opt):
    opt.add_option('--test', action='store_true',default=False,dest='_test',help='''build unit tests''')

    opt.load('compiler_c compiler_cxx')

def configure(conf):
    print "Nothing";
