# -*- Mode: python; py-indent-offset: 4; indent-tabs-mode: nil; coding: utf-8; -*-

VERSION='0.1'
APPNAME='ChronoSync'

from waflib import Configure, Build, Logs

def options(opt):
    opt.load('compiler_c compiler_cxx gnu_dirs')
    opt.load('boost doxygen sphinx_build protoc default-compiler-flags pch',
             tooldir='.waf-tools')

    syncopt = opt.add_option_group ("ChronoSync Options")

    syncopt.add_option('--debug',action='store_true', default=False, dest='debug',
                       help='''debugging mode''')
    syncopt.add_option('--with-log4cxx', action='store_true', default=False, dest='log4cxx',
                       help='''Compile with log4cxx''')
    syncopt.add_option('--with-tests', action='store_true', default=False, dest='_test',
                       help='''build unit tests''')

def configure(conf):
    conf.load('compiler_c compiler_cxx gnu_dirs boost default-compiler-flags pch')
    conf.load('doxygen sphinx_build')
    conf.load('protoc')

    conf.check_cfg(package='libndn-cxx', args=['--cflags', '--libs'], uselib_store='NDNCXX',
                   mandatory=True)

    conf.check_boost(lib='system iostreams thread unit_test_framework')

    if conf.options.log4cxx:
        conf.check_cfg(package='liblog4cxx', args=['--cflags', '--libs'], uselib_store='LOG4CXX',
                       mandatory=True)

    if conf.options._test:
      conf.define('_TEST', 1)

def build(bld):
    libsync = bld(
        target="ChronoSync",
        # vnum = "1.0.0",
        features=['cxx', 'cxxshlib'],
        source =  bld.path.ant_glob(['src/**/*.cc', 'src/**/*.proto']),
        use = 'BOOST NDNCXX',
        includes = ['src'],
        )

    # Unit tests
    if bld.get_define("_TEST"):
      unittests = bld.program(
          target="unit-tests",
          source = bld.path.ant_glob(['tests/**/*.cc']),
          features=['cxx', 'cxxprogram'],
          use = 'ChronoSync',
          includes = ['src'],
          install_path = None,
          )

    if bld.get_define("HAVE_LOG4CXX"):
        libsync.use += ' LOG4CXX'
        if bld.get_define("_TEST"):
            unittests.use += ' LOG4CXX'

    bld.install_files(
        dest = "%s/ChronoSync" % bld.env['INCLUDEDIR'],
        files = bld.path.ant_glob(['src/**/*.h']),
        cwd = bld.path.find_dir("src"),
        relative_trick = True,
        )

    bld.install_files(
        dest = "%s/ChronoSync" % bld.env['INCLUDEDIR'],
        files = bld.path.get_bld().ant_glob(['src/**/*.h']),
        cwd = bld.path.get_bld().find_dir("src"),
        relative_trick = True,
        )

    pc = bld(
        features = "subst",
        source='ChronoSync.pc.in',
        target='ChronoSync.pc',
        install_path = '${LIBDIR}/pkgconfig',
        PREFIX       = bld.env['PREFIX'],
        INCLUDEDIR   = "%s/ChronoSync" % bld.env['INCLUDEDIR'],
        VERSION      = VERSION,
        )

def doxygen(bld):
    if not bld.env.DOXYGEN:
        bld.fatal("ERROR: cannot build documentation(`doxygen' is not found in $PATH)")
    bld(features="doxygen",
         doxyfile='doc/doxygen.conf',
         output_dir = 'doc')
