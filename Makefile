#################################################################
# Pop3Client makefile (shared library + test application) 		#
# Author: HERAMBA												#
# E-mail: heramba85@gmail.com									#
# Copyright (C) HERAMBA 2011									#
#################################################################

#Version Information
MAJOR_VERSION = 0
MINOR_VERSION = 1

#Compiler
CPP = g++

#Set the highest debug level
DEBUG_MACRO = POP3_DEBUG_LEVEL
DEBUG_LEVEL = 4

LIB_EXPORT_PATH = /usr/lib
EXEFLAGS = -I. -g -Wall
CXXFLAGS = -I. -g -Wall -fPIC -D$(DEBUG_MACRO)=$(DEBUG_LEVEL)

POSTPROCESS = postprocess

LIBSO = -lcrypto -lssl -lsasl2 -lkrb5 -lrt -pthread

LIB = libpop
LIBLINK = $(LIB).so
LIBNAME = $(LIB).so.$(MAJOR_VERSION).$(MINOR_VERSION)
LIBFLAGS = -fPIC
LIBCOMMON = common/pop3base64.o common/pop3md5.o common/pop3utils.o common/pop3strtoken.o
LIBWRAPPER = wrapper/pop3krb5wrapper.o wrapper/pop3saslwrapper.o wrapper/pop3sslwrapper.o
LIBAUTH = auth/pop3authcommon.o auth/pop3clearmech.o auth/pop3apopmech.o auth/pop3anonymousmech.o auth/pop3plainmech.o auth/pop3loginmech.o auth/pop3crammd5mech.o auth/pop3digestmd5mech.o auth/pop3ntlmmech.o auth/pop3gssapimech.o auth/pop3authfactory.o
LIBSOCK = sock/pop3sockmanager.o
LIBMAIN = pop3capabilities.o pop3client.o
LIBOBJS = $(LIBCOMMON) $(LIBWRAPPER) $(LIBAUTH) $(LIBSOCK) $(LIBMAIN)

EXE = Pop3Client

.PHONY : all
all: $(LIB) $(POSTPROCESS) $(EXE)

postprocess:
	@echo -e "\n***** Copying library to $(LIB_EXPORT_PATH) *****\n"
	$(shell cp -f $(LIBNAME) $(LIB_EXPORT_PATH))
	@echo -e "***** Creating softlinks *****\n"
	$(shell ln -s $(LIB_EXPORT_PATH)/$(LIBNAME) $(LIB_EXPORT_PATH)/$(LIBLINK) 2>/dev/null)
	@echo -e "$(LIBLINK) -> $(LIBNAME)\n"
	
$(LIB): $(LIBOBJS)
	@echo -e "\n***** Creating shared library *****\n"
	$(CPP) $(LIBOBJS) $(LIBFLAGS) -shared -Wl,-soname,$(LIBLINK) -o $(LIBNAME) $(LIBSO)

$(EXE): pop3test.cpp $(LIBOBJS)
	@echo -e "***** Building test executable *****\n"
	$(CPP) $(EXEFLAGS) pop3test.cpp -L. -o $(EXE) -lpop

.PHONY : clean
clean:
	@echo Removing $(LIBOBJS)
	$(shell rm -f $(LIBOBJS) 2>&1>/dev/null)
	@echo Removing LIBS
	$(shell rm -f libpop.so*)
	$(shell rm -f /usr/lib/libpop.so*)
	@echo Removing $(EXE)
	$(shell rm -f $(EXE) 2>&1>/dev/null)
