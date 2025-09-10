env=Environment()
env.Program('auction', Glob('src/*.cpp'))

env.Append(CPPPATH=['inc','/usr/include/c++/9/'],
           CCFLAGS=['-g'],
           CPPDEFINES=['pthread'],
           LIBS=['rt','ssl','crypto','pthread'],
           SCONS_CXX_STANDARD="c++14"    )
