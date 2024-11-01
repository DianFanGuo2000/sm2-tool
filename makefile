


PRGM = sm2_tool



#CROSS_COMPILE=/home/mj/work/crosstool/arm_eabi_gcc4.5.2_glibc2.13.0_fp/bin/arm-unknown-linux-gnueabi-
#CROSS_COMPILE=/home/mj/work/buildroot/output/host/usr/bin/arm-buildroot-linux-uclibcgnueabi-

#CROSS_COMPILE=/home/cjy/work/buildroot-2019.02.1/output/host/usr/bin/aarch64-buildroot-linux-gnu-

CC = $(CROSS_COMPILE)gcc
OBJCOPY = $(CROSS_COMPILE)objcopy
OBJDUMP = $(CROSS_COMPILE)objdump
NM = $(CROSS_COMPILE)nm
CPPFLAGS =
LDFLAGS = 
CFLAGS = -Wall 
COMPILE = $(CC) $(CPPFLAGS) $(CFLAGS) -c
LINKCC = $(CC) $(LDFLAGS)
LIBA = 
SRCS := $(wildcard *.c)
DEPS := $(patsubst %.c,%.d,$(SRCS))
OBJS := $(patsubst %.c,%.o,$(SRCS))

all:$(PRGM)
#	$(OBJDUMP) -d $(PRGM) > $(PRGM).dump
#	$(NM) -v -l $(PRGM) > $(PRGM).map
	
$(PRGM):$(OBJS) $(DEPS)
	$(LINKCC) $(OBJS) $(LIBA) -o $(PRGM)
	
%.d:%.c
	$(CC) -MM $(CPPFLAGS) $< > $@
%.o:%.c
	$(COMPILE) $< -o $@
.PHONY:clean
clean:
	rm -f $(OBJS) $(DEPS) $(PRGM) *.dump *.map *.debug
explain:
	@echo "The information represents in the program:"
	@echo "Final executable name: $(PRGM)"
	@echo "Source files: $(SRCS)"
	@echo "Object files: $(OBJS)"
depend:$(DEPS)
	@echo "Dependencies are now up-to-date"
-include $(DEPS)
