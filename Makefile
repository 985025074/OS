# Building
TARGET := riscv64gc-unknown-none-elf
MODE := release
KERNEL_ELF := target/$(TARGET)/$(MODE)/os
KERNEL_BIN := kernel_$(MODE).bin
DISASM_TMP := target/$(TARGET)/$(MODE)/asm
BOOTLOADER := ../bootloader/rustsbi-qemu.bin
KERNEL_ENTRY_PA = 0x80200000;

KERNEL:
	@cargo build --$(MODE)
	@rust-objcopy --strip-all $(KERNEL_ELF) -O binary $(KERNEL_BIN)
	@echo "Build $(KERNEL_BIN) successfully."

# if stuck use CTRL-A X to exit QEMU
run: KERNEL
	@qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-bios $(BOOTLOADER) \
		-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA) -m 1G
debug:KERNEL
	@qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-s -S \
		-bios $(BOOTLOADER) \
		-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA) -m 1G
client_gdb:
	@./elf-gdb \
		-ex 'file $(KERNEL_ELF)' \
		-ex 'set arch riscv:rv64' \
		-ex 'target remote localhost:1234'
		-ex 'display/10i $pc' \

