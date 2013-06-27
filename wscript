# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-
APPNAME = 'ndnsec'
VERSION = '0.1'

from waflib import Build, Logs, Utils, Task, TaskGen, Configure;

def options(opt):
    opt.load('compiler_c compiler_cxx boost c_osx')

def configure(conf):
    conf.load('compiler_c compiler_cxx boost c_osx')

    conf.add_supported_cxxflags (cxxflags = ['-O0',
                                             '-Wall',
                                             '-Wno-unused-variable',
                                             '-g3',
                                             '-Wno-unused-private-field', # only clang supports
                                             '-fcolor-diagnostics',       # only clang supports
                                             '-Qunused-arguments'         # only clang supports
                                             ])

    if Utils.unversioned_sys_platform () == "darwin":
        conf.check_cxx(framework_name='Foundation', uselib_store='OSX_FOUNDATION', mandatory=True, compile_filename='test.mm')
        conf.check_cxx(framework_name='AppKit',     uselib_store='OSX_APPKIT',     mandatory=True, compile_filename='test.mm')
        conf.check_cxx(framework_name='Security',   uselib_store='OSX_SECURITY',   define_name='HAVE_SECURITY',
                       use="OSX_FOUNDATION", mandatory=True, compile_filename='test.mm')


    conf.check_cfg(package='liblog4cxx', args=['--cflags', '--libs'], uselib_store='LOG4CXX', mandatory=True)
    conf.define ("HAVE_LOG4CXX", 1)

    conf.check_boost(lib='system test iostreams filesystem thread date_time')

    conf.write_config_header('config.h')

def build(bld):
    bld.program(
        target = 'app1',
        features = "cxx cxxprogram",
        defines = "WAF",
        source = bld.path.ant_glob(['private/*.cc', 'private/*.mm']),
        use = 'BOOST_TEST BOOST_FILESYSTEM BOOST_DATE_TIME LOG4CXX OSX_FOUNDATION OSX_SECURITY',
        includes = ".",
        install_prefix = None,
        )

@Configure.conf
def add_supported_cxxflags(self, cxxflags):
    """
    Check which cxxflags are supported by compiler and add them to env.CXXFLAGS variable
    """
    self.start_msg('Checking allowed flags for c++ compiler')

    supportedFlags = []
    for flag in cxxflags:
        if self.check_cxx (cxxflags=[flag], mandatory=False):
            supportedFlags += [flag]

    self.end_msg (' '.join (supportedFlags))
    self.env.CXXFLAGS += supportedFlags

    
@TaskGen.extension('.mm')
def mm_hook(self, node):
    """Alias .mm files to be compiled the same as .cc files, gcc will do the right thing."""
    return self.create_compiled_task('cxx', node)
