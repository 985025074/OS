# Building
TARGET := riscv64gc-unknown-none-elf
MODE := release
APP_DIR = ./results
KERNEL_ELF := target/$(TARGET)/$(MODE)/os
KERNEL_BIN := kernel_$(MODE).bin
DISASM_TMP := target/$(TARGET)/$(MODE)/asm
FS_IMG := ../user/target/$(TARGET)/$(MODE)/fs.img
KERNEL_ENTRY_PA = 0x80200000
SMP ?= 4
MEM ?= 1G
DISK_IMG ?=
# Optional OpenSBI fw_dynamic for HSM-enabled boot
FW_DYNAMIC ?=../firmware/fw_dynamic.bin
# Only append the extra virtio disk if the file exists
ifneq (,$(wildcard $(DISK_IMG)))
DISK_ARGS := -drive file=$(DISK_IMG),if=none,format=raw,id=x1 -device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1
else
DISK_ARGS :=
endif
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
	@# `rust-objcopy` is optional; QEMU boots the ELF directly.
	@OBJCOPY=$$(command -v rust-objcopy || command -v llvm-objcopy || true); \
	if [ -n "$$OBJCOPY" ]; then \
		$$OBJCOPY --strip-all $(KERNEL_ELF) -O binary $(KERNEL_BIN); \
		echo "Build $(KERNEL_BIN) successfully."; \
	else \
		echo "⚠️  No objcopy found; skip generating $(KERNEL_BIN) (QEMU uses ELF)."; \
	fi
	@cp $(KERNEL_ELF) kernel_$(MODE).elf

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
		-kernel $(KERNEL_ELF) \
		-m $(MEM) \
		-smp $(SMP) \
		-nographic \
		-bios default \
		-drive file=$(FS_IMG),if=none,format=raw,id=x0 \
		-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
		-no-reboot \
		-device virtio-net-device,netdev=net \
		-netdev user,id=net \
		-rtc base=utc \
		$(DISK_ARGS)



test:KERNEL
	@cd ../tests && cargo test -- --nocapture

debug:KERNEL
	@qemu-system-riscv64 \
		-machine virt \
		-kernel $(KERNEL_ELF) \
		-nographic \
		-s -S \
		-bios default \
		-m $(MEM) \
		-smp $(SMP) \
		-drive file=$(FS_IMG),if=none,format=raw,id=x0 \
		-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0

# ===========================
# Ext4 Support
# ===========================
EXT4_IMG := ../ext4-fs-packer/target/fs.ext4

# Build ext4 image from user apps
ext4_img: USER_APPS
	@echo "🔧 Building ext4 filesystem image..."
	@cd ../ext4-fs-packer && cargo run --release -- \
		-u ../os/$(APP_DIR) \
		-t target \
		-S 64M
	@echo "✅ Ext4 image created: $(EXT4_IMG)"

# Run with ext4 filesystem
run_ext4: KERNEL ext4_img
	@echo "🔍 Running QEMU with ext4 VirtIO block device..."
	@echo "   ➜ File System Image: $(EXT4_IMG)"
	qemu-system-riscv64 \
		-machine virt \
		-kernel $(KERNEL_ELF) \
		-m $(MEM) \
		-smp $(SMP) \
		-nographic \
		-bios default \
		-drive file=$(EXT4_IMG),if=none,format=raw,id=x0 \
		-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
		-no-reboot \
		-device virtio-net-device,netdev=net \
		-netdev user,id=net \
		-rtc base=utc \
		$(DISK_ARGS)
run_ext4_hsm: KERNEL ext4_img
	@echo "🔍 Running QEMU with ext4 VirtIO block device..."
	@echo "   ➜ File System Image: $(EXT4_IMG)"
	@test -f $(FW_DYNAMIC) || (echo "❌ fw_dynamic not found at $(FW_DYNAMIC). Set FW_DYNAMIC=path/to/fw_dynamic.bin"; exit 1)
	qemu-system-riscv64 \
		-machine virt \
		-kernel $(KERNEL_ELF) \
		-m $(MEM) \
		-smp $(SMP) \
		-nographic \
		-bios $(FW_DYNAMIC) \
		-drive file=$(EXT4_IMG),if=none,format=raw,id=x0 \
		-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0 \
		-no-reboot \
		-device virtio-net-device,netdev=net \
		-netdev user,id=net \
		-rtc base=utc \
		$(DISK_ARGS)

# Debug with ext4 filesystem
debug_ext4: KERNEL ext4_img
	@echo "🐛 Debugging with ext4 filesystem..."
	@qemu-system-riscv64 \
		-machine virt \
		-kernel $(KERNEL_ELF) \
		-nographic \
		-s -S \
		-bios default \
		-m $(MEM) \
		-smp $(SMP) \
		-drive file=$(EXT4_IMG),if=none,format=raw,id=x0 \
		-device virtio-blk-device,drive=x0,bus=virtio-mmio-bus.0

client_gdb:
	@./elf-gdb \
		-ex 'file $(KERNEL_ELF)' \
		-ex 'set arch riscv:rv64' \
		-ex 'target remote localhost:1234'
		-ex 'display/10i $pc' 
