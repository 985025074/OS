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
MEM ?= 512M
QEMU_TIMEOUT ?= 0
DISK_IMG ?= ../sdcard-rv.img
EXT4_REBUILD ?= 0
SUBMIT ?= 0
USER_FEATURES :=
ifeq ($(SUBMIT),1)
USER_FEATURES := --features submit
endif
# Optional OpenSBI fw_dynamic for HSM-enabled boot
FW_DYNAMIC ?=../firmware/fw_dynamic.bin
# Only append the extra virtio disk if the file exists
ifneq (,$(wildcard $(DISK_IMG)))
DISK_ARGS := -drive file=$(DISK_IMG),if=none,format=raw,id=x1 -device virtio-blk-device,drive=x1,bus=virtio-mmio-bus.1
else
DISK_ARGS :=
endif

ifeq ($(QEMU_TIMEOUT),0)
QEMU_RUN := qemu-system-riscv64
else
QEMU_RUN := timeout $(QEMU_TIMEOUT) qemu-system-riscv64
endif

# build kernel and copy it to save_dir 
KERNEL:USER_APPS 
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

# find all excutable in the user's target dir strip it and copy to the os_str
USER_APPS:
	@cd ../user  && cargo build --$(MODE) $(USER_FEATURES)
	@for f in ../user/target/$(TARGET)/$(MODE)/*; do \
		if [ -f "$$f" ] && [ -x "$$f" ]; then \
			base=$$(basename $$f); \
			dst=../os/$(APP_DIR)/$$base.bin; \
			if [ ! -f "$$dst" ] || ! cmp -s "$$f" "$$dst"; then \
				cp "$$f" "$$dst"; \
				echo "find user app (updated): $$base"; \
			else \
				echo "find user app (cached): $$base"; \
			fi; \
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
	$(QEMU_RUN) \
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
EXT4_SIZE?= 4G 
EXT4_BASE_IMG ?= ../img/disk.img
EXT4_BASE_TAR ?= ../img/disk.tar
EXT4_BASE_TAR_XZ ?= ../img/disk.tar.xz
EXT4_BASE_ARG :=
ifneq ($(strip $(EXT4_BASE_IMG)),)
EXT4_BASE_ARG := -b $(abspath $(EXT4_BASE_IMG))
EXT4_BASE_DEP := ext4_base_img
endif
# Build ext4 image from user apps
# check if need to rebuild
# 1. ext4 image not exist
# 2. any user app is newer than ext4 image
# 3. any file in extra/ is newer than ext4 image
# 4. base image is newer than ext4 image
# 5. EXT4_REBUILD is set to 1

ext4_img: USER_APPS $(EXT4_BASE_DEP)
	@needs=0; \
	if [ ! -f "$(EXT4_IMG)" ]; then needs=1; fi; \
	if [ $$needs -eq 0 ]; then \
		if find "$(APP_DIR)" -type f -newer "$(EXT4_IMG)" 2>/dev/null | head -n 1 | grep -q .; then needs=1; fi; \
	fi; \
	if [ $$needs -eq 0 ]; then \
		if find ../ext4-fs-packer/extra -type f -newer "$(EXT4_IMG)" 2>/dev/null | head -n 1 | grep -q .; then needs=1; fi; \
	fi; \
	if [ $$needs -eq 0 ] && [ -n "$(EXT4_BASE_IMG)" ] && [ -f "$(EXT4_BASE_IMG)" ]; then \
		if [ "$(EXT4_BASE_IMG)" -nt "$(EXT4_IMG)" ]; then needs=1; fi; \
	fi; \
	if [ "$(EXT4_REBUILD)" = "1" ]; then needs=1; fi; \
	if [ $$needs -eq 0 ]; then \
		echo "✅ Reusing existing ext4 image: $(EXT4_IMG)"; \
	else \
		echo "🔧 Building ext4 filesystem image..."; \
		cd ../ext4-fs-packer && cargo run --release -- \
			-u ../os/$(APP_DIR) \
			-e extra \
			$(EXT4_BASE_ARG) \
			-t target \
			-S $(EXT4_SIZE); \
		echo "✅ Ext4 image created: $(EXT4_IMG)"; \
	fi

ext4_base_img:
	@if [ ! -f "$(EXT4_BASE_IMG)" ]; then \
		if [ -f "$(EXT4_BASE_TAR)" ]; then \
			echo "📦 Extracting base image from $(EXT4_BASE_TAR)..."; \
			tar -xf "$(EXT4_BASE_TAR)" -C "$(dir $(EXT4_BASE_IMG))"; \
		elif [ -f "$(EXT4_BASE_TAR_XZ)" ]; then \
			echo "📦 Extracting base image from $(EXT4_BASE_TAR_XZ)..."; \
			tar -xf "$(EXT4_BASE_TAR_XZ)" -C "$(dir $(EXT4_BASE_IMG))"; \
		else \
			echo "❌ Base image not found: $(EXT4_BASE_IMG)"; \
			exit 1; \
		fi; \
	fi

# Run with ext4 filesystem
run_ext4: KERNEL ext4_img
	@echo "🔍 Running QEMU with ext4 VirtIO block device..."
	@echo "   ➜ File System Image: $(EXT4_IMG)"
	$(QEMU_RUN) \
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
	$(QEMU_RUN) \
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
