# Building
TARGET := riscv64gc-unknown-none-elf
MODE := release
APP_DIR = ./results
KERNEL_ELF := target/$(TARGET)/$(MODE)/os
KERNEL_BIN := kernel_$(MODE).bin
DISASM_TMP := target/$(TARGET)/$(MODE)/asm
BOOTLOADER := ../bootloader/rustsbi-qemu.bin
FS_IMG := ../user/target/$(TARGET)/$(MODE)/fs.img
KERNEL_ENTRY_PA = 0x80200000
# ===========================
# VirtIO Support Check
# ===========================

check_virtio:
	@echo "🔍 Checking VirtIO device support in QEMU..."
	@VIRTIO_MMIO=$$(qemu-system-riscv64 -device help | grep -c virtio-mmio); \
	VIRTIO_BLK=$$(qemu-system-riscv64 -device help | grep -c virtio-blk-device); \
	if [ $$VIRTIO_MMIO -eq 0 ]; then \
		echo "\033[31m[ERROR]\033[0m QEMU missing 'virtio-mmio' support!"; \
		echo "  ➜ Please ensure you installed 'qemu-system-riscv64' with VirtIO support."; \
		exit 1; \
	fi; \
	if [ $$VIRTIO_BLK -eq 0 ]; then \
		echo "\033[31m[ERROR]\033[0m QEMU missing 'virtio-blk-device' support!"; \
		echo "  ➜ Use: sudo apt install qemu-system-misc  (on Ubuntu/Debian)"; \
		exit 1; \
	fi; \
	echo "\033[32m[SUCCESS]\033[0m VirtIO support detected: virtio-mmio & virtio-blk-device are available."

# build kernel and copy it to save_dir 
KERNEL:USER_APPS FILE_IMAGHE
	@cargo build --$(MODE)
	@rust-objcopy --strip-all $(KERNEL_ELF) -O binary $(KERNEL_BIN)
	@cp $(KERNEL_ELF) kernel_$(MODE).elf
	@echo "Build $(KERNEL_BIN) successfully."

FILE_IMAGHE: USER_APPS
	@cd ../easy-fs-fuse && cargo run --release -- -s ../user/src/bin/ -t ../user/target/riscv64gc-unknown-none-elf/release/
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
# now address
	echo "🔍 Running QEMU with VirtIO block device..."
	echo "   ➜ File System Image: $(FS_IMG)"
	echo "pwd is $(shell pwd)"
	qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-bios $(BOOTLOADER) \
		-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA) \
		-m 1G \
		-drive file=$(FS_IMG),if=none,format=raw,id=x0 \
		-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0



test:KERNEL
	@cd ../tests && cargo test -- --nocapture

debug:KERNEL
	@qemu-system-riscv64 \
		-machine virt \
		-nographic \
		-s -S \
		-bios $(BOOTLOADER) \
		-device loader,file=$(KERNEL_BIN),addr=$(KERNEL_ENTRY_PA) -m 1G \
		-drive file=$(FS_IMG),if=none,format=raw,id=x0 \
		-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0
client_gdb:
	@./elf-gdb \
		-ex 'file $(KERNEL_ELF)' \
		-ex 'set arch riscv:rv64' \
		-ex 'target remote localhost:1234'
		-ex 'display/10i $pc' 

