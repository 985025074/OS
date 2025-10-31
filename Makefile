# Building
TARGET := riscv64gc-unknown-none-elf
MODE := release
APP_DIR = ./results
KERNEL_ELF := target/$(TARGET)/$(MODE)/os
KERNEL_BIN := kernel_$(MODE).bin
DISASM_TMP := target/$(TARGET)/$(MODE)/asm
BOOTLOADER := ../bootloader/rustsbi-qemu.bin
KERNEL_ENTRY_PA = 0x80200000;

# build kernel and copy it to save_dir 
KERNEL:USER_APPS
	@cargo build --$(MODE)
	@rust-objcopy --strip-all $(KERNEL_ELF) -O binary $(KERNEL_BIN)
	@cp $(KERNEL_ELF) kernel_$(MODE).elf
	@echo "Build $(KERNEL_BIN) successfully."

# find all excutable in the user's target dir strip it and copy to the os_str
USER_APPS:
	@cd ../user  && cargo build --$(MODE)
	@for f in ../user/target/$(TARGET)/$(MODE)/*; do \
		if [ -f "$$f" ] && [ -x "$$f" ]; then \
			base=$$(basename $$f); \
			cp $$f  ../os/$(APP_DIR)/$$base.bin; \
			echo "find user app: $$base"; \
		fi; \
	done
	@echo "Build user apps successfully."

clean:
	@cargo clean
	@rm -f $(APP_DIR)/*.bin $(APP_DIR)/*.elf 
	@rm -f *.bin *.elf
	@cd ../user && cargo clean
# if stuck use CTRL-A X to exit QEMU
run: KERNEL
	@qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-bios $(BOOTLOADER) \
		-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA) -m 1G
test:KERNEL
	@cd ../tests && cargo test -- --nocapture

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

