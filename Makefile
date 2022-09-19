MACOSX_CC	= xcrun -sdk macosx gcc

CFLAGS		= -I./include -Wall
CFLAGS		+= -Os

LDFLAGS		= -framework IOKit -framework CoreFoundation

MACOSX_OBJ	= t8015_boot

SOURCE		= \
		main.c \
		io/iousb.c \
		common/common.c \
		exploit/checkm8_t8015.c

.PHONY: all clean

all: 
	# macosx
	$(MACOSX_CC) $(CFLAGS) $(BUILTIN_FLAGS) $(LDFLAGS) $(SOURCE) -o $(MACOSX_OBJ)

clean:
	-$(RM) $(MACOSX_OBJ)
