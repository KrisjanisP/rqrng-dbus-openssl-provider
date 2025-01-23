LIB_DIR=$(CURDIR)/lib
SRC_DIR=$(CURDIR)/src

compile: $(LIB_DIR)/librqrng.so

$(LIB_DIR)/librqrng.so: $(SRC_DIR)/qrng-provider-rand.c $(SRC_DIR)/qrng-provider.c
	mkdir -p $(LIB_DIR)
	gcc -shared -fPIC $^ -o $@ `pkg-config --cflags --libs libsystemd`