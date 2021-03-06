###########################################
#Makefile for simple programs
###########################################
INC:=./include
SRC:=./src
BIN:=./bin
OBJ:=./obj

CC:=/opt/hisi-linux-nptl/arm-hisiv100-linux/bin/arm-hisiv100-linux-uclibcgnueabi-gcc
#CC:=cc
CC_FLAG:=-Wall -g  -DSAVE_FILE_DEBUG -DRTSP_DEBUG
LD_FLAG:=-lpthread -lrt


SOURCES:=$(wildcard $(SRC)/*.c)
OBJS:=$(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SOURCES))
TARGET:=rtspClient

$(TARGET):$(OBJS)
	$(CC) $(CC_FLAG) -I$(INC) -o $(BIN)/$@ $(OBJS) $(LD_FLAG)
	
all:$(OBJS)
$(OBJS):$(OBJ)/%.o:$(SRC)/%.c
	$(CC) $(CC_FLAG) -I$(INC) -c $< -o $@

.PRONY:clean
clean:
	@echo "Removing linked and compiled files......"
	rm -f $(OBJ)/*.o $(BIN)/*
