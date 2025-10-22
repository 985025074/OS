
kernel_release.elf:	file format elf64-littleriscv

Disassembly of section .text:

0000000080200000 <stext>:
80200000: 00003117     	auipc	sp, 0x3
80200004: 00010113     	mv	sp, sp
80200008: 00001097     	auipc	ra, 0x1
8020000c: 2d8080e7     	jalr	0x2d8(ra) <rust_main>
		...

0000000080201000 <strampoline>:
80201000: 711d         	addi	sp, sp, -0x60
80201002: ec86         	sd	ra, 0x58(sp)
80201004: e8a2         	sd	s0, 0x50(sp)
80201006: 1080         	addi	s0, sp, 0x60
80201008: faa43423     	sd	a0, -0x58(s0)
8020100c: fa840513     	addi	a0, s0, -0x58

0000000080201010 <.Lpcrel_hi1>:
80201010: 00000597     	auipc	a1, 0x0

0000000080201014 <.Lpcrel_hi2>:
80201014: 00001617     	auipc	a2, 0x1
80201018: 4689         	li	a3, 0x2
8020101a: fc043823     	sd	zero, -0x30(s0)
8020101e: fe040713     	addi	a4, s0, -0x20
80201022: 0e058593     	addi	a1, a1, 0xe0
80201026: fea43023     	sd	a0, -0x20(s0)
8020102a: feb43423     	sd	a1, -0x18(s0)
8020102e: 4505         	li	a0, 0x1
80201030: ffc60593     	addi	a1, a2, -0x4
80201034: fab43823     	sd	a1, -0x50(s0)
80201038: fad43c23     	sd	a3, -0x48(s0)
8020103c: fce43023     	sd	a4, -0x40(s0)
80201040: fca43423     	sd	a0, -0x38(s0)
80201044: fb040513     	addi	a0, s0, -0x50
80201048: 00000097     	auipc	ra, 0x0
8020104c: 058080e7     	jalr	0x58(ra) <_ZN2os7console5print17h39e9b7444599a575E>
80201050: 00000097     	auipc	ra, 0x0
80201054: 008080e7     	jalr	0x8(ra) <_ZN2os3sbi8shutdown17hf4c806301cbe7c0cE>

0000000080201058 <_ZN2os3sbi8shutdown17hf4c806301cbe7c0cE>:
80201058: 7139         	addi	sp, sp, -0x40
8020105a: fc06         	sd	ra, 0x38(sp)
8020105c: f822         	sd	s0, 0x30(sp)
8020105e: 0080         	addi	s0, sp, 0x40
80201060: 4501         	li	a0, 0x0
80201062: 4581         	li	a1, 0x0
80201064: 4601         	li	a2, 0x0
80201066: 46a1         	li	a3, 0x8
80201068: 48a1         	li	a7, 0x8
8020106a: 00000073     	ecall

000000008020106e <.Lpcrel_hi3>:
8020106e: 00001517     	auipc	a0, 0x1
80201072: 4585         	li	a1, 0x1
80201074: fda50513     	addi	a0, a0, -0x26
80201078: fe043023     	sd	zero, -0x20(s0)
8020107c: fca43023     	sd	a0, -0x40(s0)
80201080: fcb43423     	sd	a1, -0x38(s0)
80201084: fcd43823     	sd	a3, -0x30(s0)
80201088: fc043c23     	sd	zero, -0x28(s0)

000000008020108c <.Lpcrel_hi4>:
8020108c: 00001517     	auipc	a0, 0x1
80201090: ffc50593     	addi	a1, a0, -0x4
80201094: fc040513     	addi	a0, s0, -0x40
80201098: 00001097     	auipc	ra, 0x1
8020109c: c14080e7     	jalr	-0x3ec(ra) <_ZN4core9panicking9panic_fmt17hd981144b4a491ec5E>

00000000802010a0 <_ZN2os7console5print17h39e9b7444599a575E>:
802010a0: 1101         	addi	sp, sp, -0x20
802010a2: ec06         	sd	ra, 0x18(sp)
802010a4: e822         	sd	s0, 0x10(sp)
802010a6: 1000         	addi	s0, sp, 0x20
802010a8: 862a         	mv	a2, a0

00000000802010aa <.Lpcrel_hi5>:
802010aa: 00001517     	auipc	a0, 0x1
802010ae: 06650593     	addi	a1, a0, 0x66
802010b2: fef40513     	addi	a0, s0, -0x11
802010b6: 00000097     	auipc	ra, 0x0
802010ba: 3e4080e7     	jalr	0x3e4(ra) <_ZN4core3fmt5write17h88f98981b8a86a90E>
802010be: e509         	bnez	a0, 0x802010c8 <.Lpcrel_hi6>
802010c0: 60e2         	ld	ra, 0x18(sp)
802010c2: 6442         	ld	s0, 0x10(sp)
802010c4: 6105         	addi	sp, sp, 0x20
802010c6: 8082         	ret

00000000802010c8 <.Lpcrel_hi6>:
802010c8: 00001517     	auipc	a0, 0x1

00000000802010cc <.Lpcrel_hi7>:
802010cc: 00001617     	auipc	a2, 0x1

00000000802010d0 <.Lpcrel_hi8>:
802010d0: 00001717     	auipc	a4, 0x1
802010d4: 02b00593     	li	a1, 0x2b
802010d8: ff850513     	addi	a0, a0, -0x8
802010dc: fd460693     	addi	a3, a2, -0x2c
802010e0: 02070713     	addi	a4, a4, 0x20
802010e4: fef40613     	addi	a2, s0, -0x11
802010e8: 00001097     	auipc	ra, 0x1
802010ec: b54080e7     	jalr	-0x4ac(ra) <_ZN4core6result13unwrap_failed17h5e3f8b6846658e00E>

00000000802010f0 <_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h801e6bf020a87c76E>:
802010f0: 1141         	addi	sp, sp, -0x10
802010f2: e406         	sd	ra, 0x8(sp)
802010f4: e022         	sd	s0, 0x0(sp)
802010f6: 0800         	addi	s0, sp, 0x10
802010f8: 6108         	ld	a0, 0x0(a0)
802010fa: 60a2         	ld	ra, 0x8(sp)
802010fc: 6402         	ld	s0, 0x0(sp)
802010fe: 0141         	addi	sp, sp, 0x10
80201100: 00001317     	auipc	t1, 0x1
80201104: bce30067     	jr	-0x432(t1) <_ZN73_$LT$core..panic..panic_info..PanicInfo$u20$as$u20$core..fmt..Display$GT$3fmt17h5ff76826d4c971f1E>

0000000080201108 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE>:
80201108: 1101         	addi	sp, sp, -0x20
8020110a: ec06         	sd	ra, 0x18(sp)
8020110c: e822         	sd	s0, 0x10(sp)
8020110e: 1000         	addi	s0, sp, 0x20
80201110: 08000513     	li	a0, 0x80
80201114: fe042623     	sw	zero, -0x14(s0)
80201118: 00a5f763     	bgeu	a1, a0, 0x80201126 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0x1e>
8020111c: fed40693     	addi	a3, s0, -0x13
80201120: feb40623     	sb	a1, -0x14(s0)
80201124: a885         	j	0x80201194 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0x8c>
80201126: 00b5d69b     	srliw	a3, a1, 0xb
8020112a: 03f5f513     	andi	a0, a1, 0x3f
8020112e: f8050513     	addi	a0, a0, -0x80
80201132: 0065d61b     	srliw	a2, a1, 0x6
80201136: ea91         	bnez	a3, 0x8020114a <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0x42>
80201138: fee40693     	addi	a3, s0, -0x12
8020113c: 0c066593     	ori	a1, a2, 0xc0
80201140: feb40623     	sb	a1, -0x14(s0)
80201144: fea406a3     	sb	a0, -0x13(s0)
80201148: a0b1         	j	0x80201194 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0x8c>
8020114a: 03f67613     	andi	a2, a2, 0x3f
8020114e: 0105d69b     	srliw	a3, a1, 0x10
80201152: f8060613     	addi	a2, a2, -0x80
80201156: 00c5d71b     	srliw	a4, a1, 0xc
8020115a: ee81         	bnez	a3, 0x80201172 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0x6a>
8020115c: fef40693     	addi	a3, s0, -0x11
80201160: 0e076593     	ori	a1, a4, 0xe0
80201164: feb40623     	sb	a1, -0x14(s0)
80201168: fec406a3     	sb	a2, -0x13(s0)
8020116c: fea40723     	sb	a0, -0x12(s0)
80201170: a015         	j	0x80201194 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0x8c>
80201172: ff040693     	addi	a3, s0, -0x10
80201176: 03f77713     	andi	a4, a4, 0x3f
8020117a: 81c9         	srli	a1, a1, 0x12
8020117c: f8070713     	addi	a4, a4, -0x80
80201180: ff05e593     	ori	a1, a1, -0x10
80201184: feb40623     	sb	a1, -0x14(s0)
80201188: fee406a3     	sb	a4, -0x13(s0)
8020118c: fec40723     	sb	a2, -0x12(s0)
80201190: fea407a3     	sb	a0, -0x11(s0)
80201194: fec40793     	addi	a5, s0, -0x14
80201198: 0df00293     	li	t0, 0xdf
8020119c: 0f000813     	li	a6, 0xf0
802011a0: 4885         	li	a7, 0x1
802011a2: a801         	j	0x802011b2 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0xaa>
802011a4: 0785         	addi	a5, a5, 0x1
802011a6: 4581         	li	a1, 0x0
802011a8: 4601         	li	a2, 0x0
802011aa: 00000073     	ecall
802011ae: 04d78d63     	beq	a5, a3, 0x80201208 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0x100>
802011b2: 00078583     	lb	a1, 0x0(a5)
802011b6: 0ff5f513     	zext.b	a0, a1
802011ba: fe05d5e3     	bgez	a1, 0x802011a4 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0x9c>
802011be: 0017c603     	lbu	a2, 0x1(a5)
802011c2: 01f57593     	andi	a1, a0, 0x1f
802011c6: 03f67613     	andi	a2, a2, 0x3f
802011ca: 02a2f563     	bgeu	t0, a0, 0x802011f4 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0xec>
802011ce: 0027c703     	lbu	a4, 0x2(a5)
802011d2: 061a         	slli	a2, a2, 0x6
802011d4: 03f77713     	andi	a4, a4, 0x3f
802011d8: 8e59         	or	a2, a2, a4
802011da: 03056263     	bltu	a0, a6, 0x802011fe <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0xf6>
802011de: 0037c503     	lbu	a0, 0x3(a5)
802011e2: 0791         	addi	a5, a5, 0x4
802011e4: 15f6         	slli	a1, a1, 0x3d
802011e6: 91ad         	srli	a1, a1, 0x2b
802011e8: 061a         	slli	a2, a2, 0x6
802011ea: 03f57513     	andi	a0, a0, 0x3f
802011ee: 8d51         	or	a0, a0, a2
802011f0: 8d4d         	or	a0, a0, a1
802011f2: bf55         	j	0x802011a6 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0x9e>
802011f4: 0789         	addi	a5, a5, 0x2
802011f6: 00659513     	slli	a0, a1, 0x6
802011fa: 8d51         	or	a0, a0, a2
802011fc: b76d         	j	0x802011a6 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0x9e>
802011fe: 078d         	addi	a5, a5, 0x3
80201200: 00c59513     	slli	a0, a1, 0xc
80201204: 8d51         	or	a0, a0, a2
80201206: b745         	j	0x802011a6 <_ZN4core3fmt5Write10write_char17h5f0e83c8bcfa019aE+0x9e>
80201208: 4501         	li	a0, 0x0
8020120a: 60e2         	ld	ra, 0x18(sp)
8020120c: 6442         	ld	s0, 0x10(sp)
8020120e: 6105         	addi	sp, sp, 0x20
80201210: 8082         	ret

0000000080201212 <_ZN4core3fmt5Write9write_fmt17h53edafd1a9e659d6E>:
80201212: 1141         	addi	sp, sp, -0x10
80201214: e406         	sd	ra, 0x8(sp)
80201216: e022         	sd	s0, 0x0(sp)
80201218: 0800         	addi	s0, sp, 0x10
8020121a: 862e         	mv	a2, a1

000000008020121c <.Lpcrel_hi9>:
8020121c: 00001597     	auipc	a1, 0x1
80201220: ef458593     	addi	a1, a1, -0x10c
80201224: 60a2         	ld	ra, 0x8(sp)
80201226: 6402         	ld	s0, 0x0(sp)
80201228: 0141         	addi	sp, sp, 0x10
8020122a: 00000317     	auipc	t1, 0x0
8020122e: 27030067     	jr	0x270(t1) <_ZN4core3fmt5write17h88f98981b8a86a90E>

0000000080201232 <_ZN53_$LT$core..fmt..Error$u20$as$u20$core..fmt..Debug$GT$3fmt17hd4e28899c719f939E>:
80201232: 1141         	addi	sp, sp, -0x10
80201234: e406         	sd	ra, 0x8(sp)
80201236: e022         	sd	s0, 0x0(sp)
80201238: 0800         	addi	s0, sp, 0x10

000000008020123a <.Lpcrel_hi10>:
8020123a: 00001517     	auipc	a0, 0x1
8020123e: ece50693     	addi	a3, a0, -0x132
80201242: 4615         	li	a2, 0x5
80201244: 852e         	mv	a0, a1
80201246: 85b6         	mv	a1, a3
80201248: 60a2         	ld	ra, 0x8(sp)
8020124a: 6402         	ld	s0, 0x0(sp)
8020124c: 0141         	addi	sp, sp, 0x10
8020124e: 00001317     	auipc	t1, 0x1
80201252: 85430067     	jr	-0x7ac(t1) <_ZN57_$LT$core..fmt..Formatter$u20$as$u20$core..fmt..Write$GT$9write_str17h49dd41e699fcd1f7E>

0000000080201256 <_ZN56_$LT$os..console..Stdout$u20$as$u20$core..fmt..Write$GT$9write_str17h2a565f55ce35ab87E>:
80201256: c259         	beqz	a2, 0x802012dc <_ZN56_$LT$os..console..Stdout$u20$as$u20$core..fmt..Write$GT$9write_str17h2a565f55ce35ab87E+0x86>
80201258: 1141         	addi	sp, sp, -0x10
8020125a: e406         	sd	ra, 0x8(sp)
8020125c: e022         	sd	s0, 0x0(sp)
8020125e: 0800         	addi	s0, sp, 0x10
80201260: 86ae         	mv	a3, a1
80201262: 00c58733     	add	a4, a1, a2
80201266: 0df00293     	li	t0, 0xdf
8020126a: 0f000813     	li	a6, 0xf0
8020126e: 4885         	li	a7, 0x1
80201270: a801         	j	0x80201280 <_ZN56_$LT$os..console..Stdout$u20$as$u20$core..fmt..Write$GT$9write_str17h2a565f55ce35ab87E+0x2a>
80201272: 0685         	addi	a3, a3, 0x1
80201274: 4581         	li	a1, 0x0
80201276: 4601         	li	a2, 0x0
80201278: 00000073     	ecall
8020127c: 04e68d63     	beq	a3, a4, 0x802012d6 <_ZN56_$LT$os..console..Stdout$u20$as$u20$core..fmt..Write$GT$9write_str17h2a565f55ce35ab87E+0x80>
80201280: 00068583     	lb	a1, 0x0(a3)
80201284: 0ff5f513     	zext.b	a0, a1
80201288: fe05d5e3     	bgez	a1, 0x80201272 <_ZN56_$LT$os..console..Stdout$u20$as$u20$core..fmt..Write$GT$9write_str17h2a565f55ce35ab87E+0x1c>
8020128c: 0016c603     	lbu	a2, 0x1(a3)
80201290: 01f57593     	andi	a1, a0, 0x1f
80201294: 03f67613     	andi	a2, a2, 0x3f
80201298: 02a2f563     	bgeu	t0, a0, 0x802012c2 <_ZN56_$LT$os..console..Stdout$u20$as$u20$core..fmt..Write$GT$9write_str17h2a565f55ce35ab87E+0x6c>
8020129c: 0026c783     	lbu	a5, 0x2(a3)
802012a0: 061a         	slli	a2, a2, 0x6
802012a2: 03f7f793     	andi	a5, a5, 0x3f
802012a6: 8e5d         	or	a2, a2, a5
802012a8: 03056263     	bltu	a0, a6, 0x802012cc <_ZN56_$LT$os..console..Stdout$u20$as$u20$core..fmt..Write$GT$9write_str17h2a565f55ce35ab87E+0x76>
802012ac: 0036c503     	lbu	a0, 0x3(a3)
802012b0: 0691         	addi	a3, a3, 0x4
802012b2: 15f6         	slli	a1, a1, 0x3d
802012b4: 91ad         	srli	a1, a1, 0x2b
802012b6: 061a         	slli	a2, a2, 0x6
802012b8: 03f57513     	andi	a0, a0, 0x3f
802012bc: 8d51         	or	a0, a0, a2
802012be: 8d4d         	or	a0, a0, a1
802012c0: bf55         	j	0x80201274 <_ZN56_$LT$os..console..Stdout$u20$as$u20$core..fmt..Write$GT$9write_str17h2a565f55ce35ab87E+0x1e>
802012c2: 0689         	addi	a3, a3, 0x2
802012c4: 00659513     	slli	a0, a1, 0x6
802012c8: 8d51         	or	a0, a0, a2
802012ca: b76d         	j	0x80201274 <_ZN56_$LT$os..console..Stdout$u20$as$u20$core..fmt..Write$GT$9write_str17h2a565f55ce35ab87E+0x1e>
802012cc: 068d         	addi	a3, a3, 0x3
802012ce: 00c59513     	slli	a0, a1, 0xc
802012d2: 8d51         	or	a0, a0, a2
802012d4: b745         	j	0x80201274 <_ZN56_$LT$os..console..Stdout$u20$as$u20$core..fmt..Write$GT$9write_str17h2a565f55ce35ab87E+0x1e>
802012d6: 60a2         	ld	ra, 0x8(sp)
802012d8: 6402         	ld	s0, 0x0(sp)
802012da: 0141         	addi	sp, sp, 0x10
802012dc: 4501         	li	a0, 0x0
802012de: 8082         	ret

00000000802012e0 <rust_main>:
802012e0: 715d         	addi	sp, sp, -0x50
802012e2: e486         	sd	ra, 0x48(sp)
802012e4: e0a2         	sd	s0, 0x40(sp)
802012e6: fc26         	sd	s1, 0x38(sp)
802012e8: f84a         	sd	s2, 0x30(sp)
802012ea: 0880         	addi	s0, sp, 0x50

00000000802012ec <.Lpcrel_hi11>:
802012ec: 00001517     	auipc	a0, 0x1
802012f0: 4905         	li	s2, 0x1
802012f2: fc043823     	sd	zero, -0x30(s0)
802012f6: 44a1         	li	s1, 0x8
802012f8: e6c50513     	addi	a0, a0, -0x194
802012fc: faa43823     	sd	a0, -0x50(s0)
80201300: fb243c23     	sd	s2, -0x48(s0)
80201304: fc943023     	sd	s1, -0x40(s0)
80201308: fc043423     	sd	zero, -0x38(s0)
8020130c: fb040513     	addi	a0, s0, -0x50
80201310: 00000097     	auipc	ra, 0x0
80201314: d90080e7     	jalr	-0x270(ra) <_ZN2os7console5print17h39e9b7444599a575E>

0000000080201318 <.Lpcrel_hi12>:
80201318: 00001517     	auipc	a0, 0x1
8020131c: fc043823     	sd	zero, -0x30(s0)
80201320: e5850513     	addi	a0, a0, -0x1a8
80201324: faa43823     	sd	a0, -0x50(s0)
80201328: fb243c23     	sd	s2, -0x48(s0)
8020132c: fc943023     	sd	s1, -0x40(s0)
80201330: fc043423     	sd	zero, -0x38(s0)

0000000080201334 <.Lpcrel_hi13>:
80201334: 00001517     	auipc	a0, 0x1
80201338: e4c50593     	addi	a1, a0, -0x1b4
8020133c: fb040513     	addi	a0, s0, -0x50
80201340: 00001097     	auipc	ra, 0x1
80201344: 96c080e7     	jalr	-0x694(ra) <_ZN4core9panicking9panic_fmt17hd981144b4a491ec5E>

0000000080201348 <_ZN42_$LT$$RF$T$u20$as$u20$core..fmt..Debug$GT$3fmt17haf5595faf4158cecE>:
80201348: 6510         	ld	a2, 0x8(a0)
8020134a: 6108         	ld	a0, 0x0(a0)
8020134c: 6e1c         	ld	a5, 0x18(a2)
8020134e: 8782         	jr	a5

0000000080201350 <_ZN44_$LT$$RF$T$u20$as$u20$core..fmt..Display$GT$3fmt17h324d8f8b4b109971E>:
80201350: 6114         	ld	a3, 0x0(a0)
80201352: 6510         	ld	a2, 0x8(a0)
80201354: 852e         	mv	a0, a1
80201356: 85b6         	mv	a1, a3
80201358: 00000317     	auipc	t1, 0x0
8020135c: 58630067     	jr	0x586(t1) <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE>

0000000080201360 <_ZN4core3fmt3num3imp52_$LT$impl$u20$core..fmt..Display$u20$for$u20$u32$GT$3fmt17h7d58b8f06a843933E>:
80201360: 7179         	addi	sp, sp, -0x30
80201362: f406         	sd	ra, 0x28(sp)
80201364: f022         	sd	s0, 0x20(sp)
80201366: ec26         	sd	s1, 0x18(sp)
80201368: 1800         	addi	s0, sp, 0x30
8020136a: 882e         	mv	a6, a1
8020136c: 00052883     	lw	a7, 0x0(a0)
80201370: 3e800593     	li	a1, 0x3e8

0000000080201374 <.Lpcrel_hi103>:
80201374: 00001517     	auipc	a0, 0x1
80201378: e2450e13     	addi	t3, a0, -0x1dc
8020137c: 4fa9         	li	t6, 0xa
8020137e: 10b8e963     	bltu	a7, a1, 0x80201490 <.Lpcrel_hi103+0x11c>
80201382: fe740793     	addi	a5, s0, -0x19
80201386: d1b71337     	lui	t1, 0xd1b71
8020138a: 6389         	lui	t2, 0x2
8020138c: 6685         	lui	a3, 0x1
8020138e: 06400293     	li	t0, 0x64
80201392: 00989637     	lui	a2, 0x989
80201396: 75930593     	addi	a1, t1, 0x759
8020139a: 71038313     	addi	t1, t2, 0x710
8020139e: 47b68393     	addi	t2, a3, 0x47b
802013a2: 02059e93     	slli	t4, a1, 0x20
802013a6: 67f60f13     	addi	t5, a2, 0x67f
802013aa: 8546         	mv	a0, a7
802013ac: 86aa         	mv	a3, a0
802013ae: 1ff1         	addi	t6, t6, -0x4
802013b0: 1502         	slli	a0, a0, 0x20
802013b2: 03d53533     	mulhu	a0, a0, t4
802013b6: 9135         	srli	a0, a0, 0x2d
802013b8: 026505b3     	mul	a1, a0, t1
802013bc: 40b6863b     	subw	a2, a3, a1
802013c0: 03061593     	slli	a1, a2, 0x30
802013c4: 91c9         	srli	a1, a1, 0x32
802013c6: 027585b3     	mul	a1, a1, t2
802013ca: 0105d713     	srli	a4, a1, 0x10
802013ce: 81c5         	srli	a1, a1, 0x11
802013d0: 025585b3     	mul	a1, a1, t0
802013d4: 7fe77713     	andi	a4, a4, 0x7fe
802013d8: 9e0d         	subw	a2, a2, a1
802013da: 9772         	add	a4, a4, t3
802013dc: 1646         	slli	a2, a2, 0x31
802013de: 9241         	srli	a2, a2, 0x30
802013e0: 9672         	add	a2, a2, t3
802013e2: 00074583     	lbu	a1, 0x0(a4)
802013e6: 00174703     	lbu	a4, 0x1(a4)
802013ea: 00064483     	lbu	s1, 0x0(a2)
802013ee: 00164603     	lbu	a2, 0x1(a2)
802013f2: feb78ea3     	sb	a1, -0x3(a5)
802013f6: fee78f23     	sb	a4, -0x2(a5)
802013fa: fe978fa3     	sb	s1, -0x1(a5)
802013fe: 00c78023     	sb	a2, 0x0(a5)
80201402: 17f1         	addi	a5, a5, -0x4
80201404: fadf64e3     	bltu	t5, a3, 0x802013ac <.Lpcrel_hi103+0x38>
80201408: 45a5         	li	a1, 0x9
8020140a: 04a5f263     	bgeu	a1, a0, 0x8020144e <.Lpcrel_hi103+0xda>
8020140e: 03051593     	slli	a1, a0, 0x30
80201412: 6605         	lui	a2, 0x1
80201414: 06400693     	li	a3, 0x64
80201418: fde40713     	addi	a4, s0, -0x22
8020141c: 91c9         	srli	a1, a1, 0x32
8020141e: 47b60613     	addi	a2, a2, 0x47b
80201422: 01f707b3     	add	a5, a4, t6
80201426: 02c585b3     	mul	a1, a1, a2
8020142a: 81c5         	srli	a1, a1, 0x11
8020142c: 02d58633     	mul	a2, a1, a3
80201430: 9d11         	subw	a0, a0, a2
80201432: 1546         	slli	a0, a0, 0x31
80201434: 9141         	srli	a0, a0, 0x30
80201436: 9572         	add	a0, a0, t3
80201438: 00054603     	lbu	a2, 0x0(a0)
8020143c: 00154503     	lbu	a0, 0x1(a0)
80201440: 1ff9         	addi	t6, t6, -0x2
80201442: 977e         	add	a4, a4, t6
80201444: 00c70023     	sb	a2, 0x0(a4)
80201448: fea78fa3     	sb	a0, -0x1(a5)
8020144c: 852e         	mv	a0, a1
8020144e: 00088363     	beqz	a7, 0x80201454 <.Lpcrel_hi103+0xe0>
80201452: cd01         	beqz	a0, 0x8020146a <.Lpcrel_hi103+0xf6>
80201454: 0015151b     	slliw	a0, a0, 0x1
80201458: 9572         	add	a0, a0, t3
8020145a: 00154503     	lbu	a0, 0x1(a0)
8020145e: 1ffd         	addi	t6, t6, -0x1
80201460: fde40593     	addi	a1, s0, -0x22
80201464: 95fe         	add	a1, a1, t6
80201466: 00a58023     	sb	a0, 0x0(a1)
8020146a: 4529         	li	a0, 0xa
8020146c: fde40713     	addi	a4, s0, -0x22
80201470: 41f507b3     	sub	a5, a0, t6
80201474: 977e         	add	a4, a4, t6
80201476: 4585         	li	a1, 0x1
80201478: 4605         	li	a2, 0x1
8020147a: 8542         	mv	a0, a6
8020147c: 4681         	li	a3, 0x0
8020147e: 00000097     	auipc	ra, 0x0
80201482: 210080e7     	jalr	0x210(ra) <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E>
80201486: 70a2         	ld	ra, 0x28(sp)
80201488: 7402         	ld	s0, 0x20(sp)
8020148a: 64e2         	ld	s1, 0x18(sp)
8020148c: 6145         	addi	sp, sp, 0x30
8020148e: 8082         	ret
80201490: 8546         	mv	a0, a7
80201492: 45a5         	li	a1, 0x9
80201494: f715ede3     	bltu	a1, a7, 0x8020140e <.Lpcrel_hi103+0x9a>
80201498: bf5d         	j	0x8020144e <.Lpcrel_hi103+0xda>

000000008020149a <_ZN4core3fmt5write17h88f98981b8a86a90E>:
8020149a: 7159         	addi	sp, sp, -0x70
8020149c: f486         	sd	ra, 0x68(sp)
8020149e: f0a2         	sd	s0, 0x60(sp)
802014a0: eca6         	sd	s1, 0x58(sp)
802014a2: e8ca         	sd	s2, 0x50(sp)
802014a4: e4ce         	sd	s3, 0x48(sp)
802014a6: e0d2         	sd	s4, 0x40(sp)
802014a8: fc56         	sd	s5, 0x38(sp)
802014aa: f85a         	sd	s6, 0x30(sp)
802014ac: f45e         	sd	s7, 0x28(sp)
802014ae: f062         	sd	s8, 0x20(sp)
802014b0: 1880         	addi	s0, sp, 0x70
802014b2: 89b2         	mv	s3, a2
802014b4: 461d         	li	a2, 0x7
802014b6: 0209b483     	ld	s1, 0x20(s3)
802014ba: 0676         	slli	a2, a2, 0x1d
802014bc: 02060613     	addi	a2, a2, 0x20
802014c0: f8a43c23     	sd	a0, -0x68(s0)
802014c4: fab43023     	sd	a1, -0x60(s0)
802014c8: fac43423     	sd	a2, -0x58(s0)
802014cc: c4e1         	beqz	s1, 0x80201594 <_ZN4core3fmt5write17h88f98981b8a86a90E+0xfa>
802014ce: 0289b503     	ld	a0, 0x28(s3)
802014d2: 10050c63     	beqz	a0, 0x802015ea <_ZN4core3fmt5write17h88f98981b8a86a90E+0x150>
802014d6: 00451593     	slli	a1, a0, 0x4
802014da: 00651613     	slli	a2, a0, 0x6
802014de: 0009bb83     	ld	s7, 0x0(s3)
802014e2: 0109ba03     	ld	s4, 0x10(s3)
802014e6: 157d         	addi	a0, a0, -0x1
802014e8: 04e1         	addi	s1, s1, 0x18
802014ea: 4a89         	li	s5, 0x2
802014ec: 40b60b33     	sub	s6, a2, a1
802014f0: 0512         	slli	a0, a0, 0x4
802014f2: 8111         	srli	a0, a0, 0x4
802014f4: 00150913     	addi	s2, a0, 0x1
802014f8: 0ba1         	addi	s7, s7, 0x8
802014fa: 4c05         	li	s8, 0x1
802014fc: 000bb603     	ld	a2, 0x0(s7)
80201500: ca11         	beqz	a2, 0x80201514 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x7a>
80201502: fa043683     	ld	a3, -0x60(s0)
80201506: f9843503     	ld	a0, -0x68(s0)
8020150a: ff8bb583     	ld	a1, -0x8(s7)
8020150e: 6e94         	ld	a3, 0x18(a3)
80201510: 9682         	jalr	a3
80201512: ed7d         	bnez	a0, 0x80201610 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x176>
80201514: ff84d503     	lhu	a0, -0x8(s1)
80201518: c50d         	beqz	a0, 0x80201542 <_ZN4core3fmt5write17h88f98981b8a86a90E+0xa8>
8020151a: 03851c63     	bne	a0, s8, 0x80201552 <_ZN4core3fmt5write17h88f98981b8a86a90E+0xb8>
8020151e: 6088         	ld	a0, 0x0(s1)
80201520: 0512         	slli	a0, a0, 0x4
80201522: 9552         	add	a0, a0, s4
80201524: 00855583     	lhu	a1, 0x8(a0)
80201528: fe84d503     	lhu	a0, -0x18(s1)
8020152c: 03550163     	beq	a0, s5, 0x8020154e <_ZN4core3fmt5write17h88f98981b8a86a90E+0xb4>
80201530: 03851763     	bne	a0, s8, 0x8020155e <_ZN4core3fmt5write17h88f98981b8a86a90E+0xc4>
80201534: ff04b503     	ld	a0, -0x10(s1)
80201538: 0512         	slli	a0, a0, 0x4
8020153a: 9552         	add	a0, a0, s4
8020153c: 00855603     	lhu	a2, 0x8(a0)
80201540: a00d         	j	0x80201562 <_ZN4core3fmt5write17h88f98981b8a86a90E+0xc8>
80201542: ffa4d583     	lhu	a1, -0x6(s1)
80201546: fe84d503     	lhu	a0, -0x18(s1)
8020154a: ff5513e3     	bne	a0, s5, 0x80201530 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x96>
8020154e: 4601         	li	a2, 0x0
80201550: a809         	j	0x80201562 <_ZN4core3fmt5write17h88f98981b8a86a90E+0xc8>
80201552: 4581         	li	a1, 0x0
80201554: fe84d503     	lhu	a0, -0x18(s1)
80201558: fd551ce3     	bne	a0, s5, 0x80201530 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x96>
8020155c: bfcd         	j	0x8020154e <_ZN4core3fmt5write17h88f98981b8a86a90E+0xb4>
8020155e: fea4d603     	lhu	a2, -0x16(s1)
80201562: 6488         	ld	a0, 0x8(s1)
80201564: 4894         	lw	a3, 0x10(s1)
80201566: 0512         	slli	a0, a0, 0x4
80201568: 00aa0733     	add	a4, s4, a0
8020156c: 6308         	ld	a0, 0x0(a4)
8020156e: 6718         	ld	a4, 0x8(a4)
80201570: fad42423     	sw	a3, -0x58(s0)
80201574: fab41623     	sh	a1, -0x54(s0)
80201578: fac41723     	sh	a2, -0x52(s0)
8020157c: f9840593     	addi	a1, s0, -0x68
80201580: 9702         	jalr	a4
80201582: e559         	bnez	a0, 0x80201610 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x176>
80201584: 0bc1         	addi	s7, s7, 0x10
80201586: fd0b0b13     	addi	s6, s6, -0x30
8020158a: 03048493     	addi	s1, s1, 0x30
8020158e: f60b17e3     	bnez	s6, 0x802014fc <_ZN4core3fmt5write17h88f98981b8a86a90E+0x62>
80201592: a0b9         	j	0x802015e0 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x146>
80201594: 0189b503     	ld	a0, 0x18(s3)
80201598: c929         	beqz	a0, 0x802015ea <_ZN4core3fmt5write17h88f98981b8a86a90E+0x150>
8020159a: 0009ba83     	ld	s5, 0x0(s3)
8020159e: 0109b483     	ld	s1, 0x10(s3)
802015a2: 0512         	slli	a0, a0, 0x4
802015a4: ff050593     	addi	a1, a0, -0x10
802015a8: 8191         	srli	a1, a1, 0x4
802015aa: 00158913     	addi	s2, a1, 0x1
802015ae: 00a48a33     	add	s4, s1, a0
802015b2: 0aa1         	addi	s5, s5, 0x8
802015b4: 000ab603     	ld	a2, 0x0(s5)
802015b8: ca11         	beqz	a2, 0x802015cc <_ZN4core3fmt5write17h88f98981b8a86a90E+0x132>
802015ba: fa043683     	ld	a3, -0x60(s0)
802015be: f9843503     	ld	a0, -0x68(s0)
802015c2: ff8ab583     	ld	a1, -0x8(s5)
802015c6: 6e94         	ld	a3, 0x18(a3)
802015c8: 9682         	jalr	a3
802015ca: e139         	bnez	a0, 0x80201610 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x176>
802015cc: 6088         	ld	a0, 0x0(s1)
802015ce: 6490         	ld	a2, 0x8(s1)
802015d0: f9840593     	addi	a1, s0, -0x68
802015d4: 9602         	jalr	a2
802015d6: ed0d         	bnez	a0, 0x80201610 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x176>
802015d8: 04c1         	addi	s1, s1, 0x10
802015da: 0ac1         	addi	s5, s5, 0x10
802015dc: fd449ce3     	bne	s1, s4, 0x802015b4 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x11a>
802015e0: 0089b503     	ld	a0, 0x8(s3)
802015e4: 00a96763     	bltu	s2, a0, 0x802015f2 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x158>
802015e8: a035         	j	0x80201614 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x17a>
802015ea: 4901         	li	s2, 0x0
802015ec: 0089b503     	ld	a0, 0x8(s3)
802015f0: c115         	beqz	a0, 0x80201614 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x17a>
802015f2: 0009b583     	ld	a1, 0x0(s3)
802015f6: 0912         	slli	s2, s2, 0x4
802015f8: f9843503     	ld	a0, -0x68(s0)
802015fc: fa043683     	ld	a3, -0x60(s0)
80201600: 992e         	add	s2, s2, a1
80201602: 00093583     	ld	a1, 0x0(s2)
80201606: 00893603     	ld	a2, 0x8(s2)
8020160a: 6e94         	ld	a3, 0x18(a3)
8020160c: 9682         	jalr	a3
8020160e: c119         	beqz	a0, 0x80201614 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x17a>
80201610: 4505         	li	a0, 0x1
80201612: a011         	j	0x80201616 <_ZN4core3fmt5write17h88f98981b8a86a90E+0x17c>
80201614: 4501         	li	a0, 0x0
80201616: 70a6         	ld	ra, 0x68(sp)
80201618: 7406         	ld	s0, 0x60(sp)
8020161a: 64e6         	ld	s1, 0x58(sp)
8020161c: 6946         	ld	s2, 0x50(sp)
8020161e: 69a6         	ld	s3, 0x48(sp)
80201620: 6a06         	ld	s4, 0x40(sp)
80201622: 7ae2         	ld	s5, 0x38(sp)
80201624: 7b42         	ld	s6, 0x30(sp)
80201626: 7ba2         	ld	s7, 0x28(sp)
80201628: 7c02         	ld	s8, 0x20(sp)
8020162a: 6165         	addi	sp, sp, 0x70
8020162c: 8082         	ret

000000008020162e <_ZN4core3fmt9Formatter12pad_integral12write_prefix17hd16b69d762c6f0fcE>:
8020162e: 7179         	addi	sp, sp, -0x30
80201630: f406         	sd	ra, 0x28(sp)
80201632: f022         	sd	s0, 0x20(sp)
80201634: ec26         	sd	s1, 0x18(sp)
80201636: e84a         	sd	s2, 0x10(sp)
80201638: e44e         	sd	s3, 0x8(sp)
8020163a: e052         	sd	s4, 0x0(sp)
8020163c: 1800         	addi	s0, sp, 0x30
8020163e: 893a         	mv	s2, a4
80201640: 8a36         	mv	s4, a3
80201642: 89ae         	mv	s3, a1
80201644: 001105b7     	lui	a1, 0x110
80201648: 00b60c63     	beq	a2, a1, 0x80201660 <_ZN4core3fmt9Formatter12pad_integral12write_prefix17hd16b69d762c6f0fcE+0x32>
8020164c: 0209b683     	ld	a3, 0x20(s3)
80201650: 84aa         	mv	s1, a0
80201652: 85b2         	mv	a1, a2
80201654: 9682         	jalr	a3
80201656: 85aa         	mv	a1, a0
80201658: 8526         	mv	a0, s1
8020165a: c199         	beqz	a1, 0x80201660 <_ZN4core3fmt9Formatter12pad_integral12write_prefix17hd16b69d762c6f0fcE+0x32>
8020165c: 4505         	li	a0, 0x1
8020165e: a005         	j	0x8020167e <_ZN4core3fmt9Formatter12pad_integral12write_prefix17hd16b69d762c6f0fcE+0x50>
80201660: 000a0e63     	beqz	s4, 0x8020167c <_ZN4core3fmt9Formatter12pad_integral12write_prefix17hd16b69d762c6f0fcE+0x4e>
80201664: 0189b783     	ld	a5, 0x18(s3)
80201668: 85d2         	mv	a1, s4
8020166a: 864a         	mv	a2, s2
8020166c: 70a2         	ld	ra, 0x28(sp)
8020166e: 7402         	ld	s0, 0x20(sp)
80201670: 64e2         	ld	s1, 0x18(sp)
80201672: 6942         	ld	s2, 0x10(sp)
80201674: 69a2         	ld	s3, 0x8(sp)
80201676: 6a02         	ld	s4, 0x0(sp)
80201678: 6145         	addi	sp, sp, 0x30
8020167a: 8782         	jr	a5
8020167c: 4501         	li	a0, 0x0
8020167e: 70a2         	ld	ra, 0x28(sp)
80201680: 7402         	ld	s0, 0x20(sp)
80201682: 64e2         	ld	s1, 0x18(sp)
80201684: 6942         	ld	s2, 0x10(sp)
80201686: 69a2         	ld	s3, 0x8(sp)
80201688: 6a02         	ld	s4, 0x0(sp)
8020168a: 6145         	addi	sp, sp, 0x30
8020168c: 8082         	ret

000000008020168e <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E>:
8020168e: 7119         	addi	sp, sp, -0x80
80201690: fc86         	sd	ra, 0x78(sp)
80201692: f8a2         	sd	s0, 0x70(sp)
80201694: f4a6         	sd	s1, 0x68(sp)
80201696: f0ca         	sd	s2, 0x60(sp)
80201698: ecce         	sd	s3, 0x58(sp)
8020169a: e8d2         	sd	s4, 0x50(sp)
8020169c: e4d6         	sd	s5, 0x48(sp)
8020169e: e0da         	sd	s6, 0x40(sp)
802016a0: fc5e         	sd	s7, 0x38(sp)
802016a2: f862         	sd	s8, 0x30(sp)
802016a4: f466         	sd	s9, 0x28(sp)
802016a6: f06a         	sd	s10, 0x20(sp)
802016a8: ec6e         	sd	s11, 0x18(sp)
802016aa: 0100         	addi	s0, sp, 0x80
802016ac: 89be         	mv	s3, a5
802016ae: 8d3a         	mv	s10, a4
802016b0: 8a36         	mv	s4, a3
802016b2: 8ab2         	mv	s5, a2
802016b4: 8baa         	mv	s7, a0
802016b6: cdbd         	beqz	a1, 0x80201734 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0xa6>
802016b8: 010bec03     	lwu	s8, 0x10(s7)
802016bc: 00200537     	lui	a0, 0x200
802016c0: 00ac7533     	and	a0, s8, a0
802016c4: 00110b37     	lui	s6, 0x110
802016c8: c119         	beqz	a0, 0x802016ce <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x40>
802016ca: 02b00b13     	li	s6, 0x2b
802016ce: 8155         	srli	a0, a0, 0x15
802016d0: 00a98cb3     	add	s9, s3, a0
802016d4: 028c1513     	slli	a0, s8, 0x28
802016d8: 06055863     	bgez	a0, 0x80201748 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0xba>
802016dc: 02000513     	li	a0, 0x20
802016e0: 0aaa7a63     	bgeu	s4, a0, 0x80201794 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x106>
802016e4: 4501         	li	a0, 0x0
802016e6: 000a0f63     	beqz	s4, 0x80201704 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x76>
802016ea: 014a85b3     	add	a1, s5, s4
802016ee: 8656         	mv	a2, s5
802016f0: 00060683     	lb	a3, 0x0(a2)
802016f4: 0605         	addi	a2, a2, 0x1
802016f6: fc06a693     	slti	a3, a3, -0x40
802016fa: 0016c693     	xori	a3, a3, 0x1
802016fe: 9536         	add	a0, a0, a3
80201700: feb618e3     	bne	a2, a1, 0x802016f0 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x62>
80201704: 9caa         	add	s9, s9, a0
80201706: 014bd903     	lhu	s2, 0x14(s7)
8020170a: 052cf463     	bgeu	s9, s2, 0x80201752 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0xc4>
8020170e: 027c1513     	slli	a0, s8, 0x27
80201712: f9a43823     	sd	s10, -0x70(s0)
80201716: 08054b63     	bltz	a0, 0x802017ac <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x11e>
8020171a: 41990633     	sub	a2, s2, s9
8020171e: 021c1513     	slli	a0, s8, 0x21
80201722: 9179         	srli	a0, a0, 0x3e
80201724: 4585         	li	a1, 0x1
80201726: 1c2e         	slli	s8, s8, 0x2b
80201728: 0ea5c263     	blt	a1, a0, 0x8020180c <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x17e>
8020172c: 10051563     	bnez	a0, 0x80201836 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1a8>
80201730: 4d81         	li	s11, 0x0
80201732: a219         	j	0x80201838 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1aa>
80201734: 010bac03     	lw	s8, 0x10(s7)
80201738: 00198c93     	addi	s9, s3, 0x1
8020173c: 02d00b13     	li	s6, 0x2d
80201740: 028c1513     	slli	a0, s8, 0x28
80201744: f8054ce3     	bltz	a0, 0x802016dc <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x4e>
80201748: 4a81         	li	s5, 0x0
8020174a: 014bd903     	lhu	s2, 0x14(s7)
8020174e: fd2ce0e3     	bltu	s9, s2, 0x8020170e <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x80>
80201752: 000bbc03     	ld	s8, 0x0(s7)
80201756: 008bb483     	ld	s1, 0x8(s7)
8020175a: 8562         	mv	a0, s8
8020175c: 85a6         	mv	a1, s1
8020175e: 865a         	mv	a2, s6
80201760: 86d6         	mv	a3, s5
80201762: 8752         	mv	a4, s4
80201764: 00000097     	auipc	ra, 0x0
80201768: eca080e7     	jalr	-0x136(ra) <_ZN4core3fmt9Formatter12pad_integral12write_prefix17hd16b69d762c6f0fcE>
8020176c: ed75         	bnez	a0, 0x80201868 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1da>
8020176e: 6c9c         	ld	a5, 0x18(s1)
80201770: 8562         	mv	a0, s8
80201772: 85ea         	mv	a1, s10
80201774: 864e         	mv	a2, s3
80201776: 70e6         	ld	ra, 0x78(sp)
80201778: 7446         	ld	s0, 0x70(sp)
8020177a: 74a6         	ld	s1, 0x68(sp)
8020177c: 7906         	ld	s2, 0x60(sp)
8020177e: 69e6         	ld	s3, 0x58(sp)
80201780: 6a46         	ld	s4, 0x50(sp)
80201782: 6aa6         	ld	s5, 0x48(sp)
80201784: 6b06         	ld	s6, 0x40(sp)
80201786: 7be2         	ld	s7, 0x38(sp)
80201788: 7c42         	ld	s8, 0x30(sp)
8020178a: 7ca2         	ld	s9, 0x28(sp)
8020178c: 7d02         	ld	s10, 0x20(sp)
8020178e: 6de2         	ld	s11, 0x18(sp)
80201790: 6109         	addi	sp, sp, 0x80
80201792: 8782         	jr	a5
80201794: 8556         	mv	a0, s5
80201796: 85d2         	mv	a1, s4
80201798: 00000097     	auipc	ra, 0x0
8020179c: 312080e7     	jalr	0x312(ra) <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E>
802017a0: 9caa         	add	s9, s9, a0
802017a2: 014bd903     	lhu	s2, 0x14(s7)
802017a6: fb2cf6e3     	bgeu	s9, s2, 0x80201752 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0xc4>
802017aa: b795         	j	0x8020170e <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x80>
802017ac: 010bbd03     	ld	s10, 0x10(s7)
802017b0: 000bbc03     	ld	s8, 0x0(s7)
802017b4: 008bbd83     	ld	s11, 0x8(s7)
802017b8: 9fe00537     	lui	a0, 0x9fe00
802017bc: 200005b7     	lui	a1, 0x20000
802017c0: 00ad7533     	and	a0, s10, a0
802017c4: 03058593     	addi	a1, a1, 0x30
802017c8: 8d4d         	or	a0, a0, a1
802017ca: 00aba823     	sw	a0, 0x10(s7)
802017ce: 8562         	mv	a0, s8
802017d0: 85ee         	mv	a1, s11
802017d2: 865a         	mv	a2, s6
802017d4: 86d6         	mv	a3, s5
802017d6: 8752         	mv	a4, s4
802017d8: 00000097     	auipc	ra, 0x0
802017dc: e56080e7     	jalr	-0x1aa(ra) <_ZN4core3fmt9Formatter12pad_integral12write_prefix17hd16b69d762c6f0fcE>
802017e0: 4a05         	li	s4, 0x1
802017e2: e541         	bnez	a0, 0x8020186a <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1dc>
802017e4: 4481         	li	s1, 0x0
802017e6: 41990533     	sub	a0, s2, s9
802017ea: 6941         	lui	s2, 0x10
802017ec: 197d         	addi	s2, s2, -0x1
802017ee: 01257ab3     	and	s5, a0, s2
802017f2: 0124f533     	and	a0, s1, s2
802017f6: 03557463     	bgeu	a0, s5, 0x8020181e <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x190>
802017fa: 020db603     	ld	a2, 0x20(s11)
802017fe: 0485         	addi	s1, s1, 0x1
80201800: 03000593     	li	a1, 0x30
80201804: 8562         	mv	a0, s8
80201806: 9602         	jalr	a2
80201808: d56d         	beqz	a0, 0x802017f2 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x164>
8020180a: a085         	j	0x8020186a <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1dc>
8020180c: 4589         	li	a1, 0x2
8020180e: 8db2         	mv	s11, a2
80201810: 02b51463     	bne	a0, a1, 0x80201838 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1aa>
80201814: 03061513     	slli	a0, a2, 0x30
80201818: 03155d93     	srli	s11, a0, 0x31
8020181c: a831         	j	0x80201838 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1aa>
8020181e: 018db683     	ld	a3, 0x18(s11)
80201822: 8562         	mv	a0, s8
80201824: f9043583     	ld	a1, -0x70(s0)
80201828: 864e         	mv	a2, s3
8020182a: 9682         	jalr	a3
8020182c: ed1d         	bnez	a0, 0x8020186a <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1dc>
8020182e: 4a01         	li	s4, 0x0
80201830: 01abb823     	sd	s10, 0x10(s7)
80201834: a81d         	j	0x8020186a <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1dc>
80201836: 8db2         	mv	s11, a2
80201838: f8c43423     	sd	a2, -0x78(s0)
8020183c: 4d01         	li	s10, 0x0
8020183e: 02bc5c13     	srli	s8, s8, 0x2b
80201842: 000bbc83     	ld	s9, 0x0(s7)
80201846: 008bbb83     	ld	s7, 0x8(s7)
8020184a: 64c1         	lui	s1, 0x10
8020184c: 14fd         	addi	s1, s1, -0x1
8020184e: 009df933     	and	s2, s11, s1
80201852: 009d7533     	and	a0, s10, s1
80201856: 03257a63     	bgeu	a0, s2, 0x8020188a <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1fc>
8020185a: 020bb603     	ld	a2, 0x20(s7)
8020185e: 0d05         	addi	s10, s10, 0x1
80201860: 8566         	mv	a0, s9
80201862: 85e2         	mv	a1, s8
80201864: 9602         	jalr	a2
80201866: d575         	beqz	a0, 0x80201852 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1c4>
80201868: 4a05         	li	s4, 0x1
8020186a: 8552         	mv	a0, s4
8020186c: 70e6         	ld	ra, 0x78(sp)
8020186e: 7446         	ld	s0, 0x70(sp)
80201870: 74a6         	ld	s1, 0x68(sp)
80201872: 7906         	ld	s2, 0x60(sp)
80201874: 69e6         	ld	s3, 0x58(sp)
80201876: 6a46         	ld	s4, 0x50(sp)
80201878: 6aa6         	ld	s5, 0x48(sp)
8020187a: 6b06         	ld	s6, 0x40(sp)
8020187c: 7be2         	ld	s7, 0x38(sp)
8020187e: 7c42         	ld	s8, 0x30(sp)
80201880: 7ca2         	ld	s9, 0x28(sp)
80201882: 7d02         	ld	s10, 0x20(sp)
80201884: 6de2         	ld	s11, 0x18(sp)
80201886: 6109         	addi	sp, sp, 0x80
80201888: 8082         	ret
8020188a: 8566         	mv	a0, s9
8020188c: 85de         	mv	a1, s7
8020188e: 865a         	mv	a2, s6
80201890: 86d6         	mv	a3, s5
80201892: 8752         	mv	a4, s4
80201894: 00000097     	auipc	ra, 0x0
80201898: d9a080e7     	jalr	-0x266(ra) <_ZN4core3fmt9Formatter12pad_integral12write_prefix17hd16b69d762c6f0fcE>
8020189c: 4a05         	li	s4, 0x1
8020189e: f571         	bnez	a0, 0x8020186a <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1dc>
802018a0: 018bb683     	ld	a3, 0x18(s7)
802018a4: 8566         	mv	a0, s9
802018a6: f9043583     	ld	a1, -0x70(s0)
802018aa: 864e         	mv	a2, s3
802018ac: 9682         	jalr	a3
802018ae: fd55         	bnez	a0, 0x8020186a <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1dc>
802018b0: 4481         	li	s1, 0x0
802018b2: f8843503     	ld	a0, -0x78(s0)
802018b6: 41b50533     	sub	a0, a0, s11
802018ba: 6941         	lui	s2, 0x10
802018bc: 197d         	addi	s2, s2, -0x1
802018be: 012579b3     	and	s3, a0, s2
802018c2: 0124f533     	and	a0, s1, s2
802018c6: 01353a33     	sltu	s4, a0, s3
802018ca: fb3570e3     	bgeu	a0, s3, 0x8020186a <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1dc>
802018ce: 020bb603     	ld	a2, 0x20(s7)
802018d2: 0485         	addi	s1, s1, 0x1
802018d4: 8566         	mv	a0, s9
802018d6: 85e2         	mv	a1, s8
802018d8: 9602         	jalr	a2
802018da: d565         	beqz	a0, 0x802018c2 <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x234>
802018dc: b779         	j	0x8020186a <_ZN4core3fmt9Formatter12pad_integral17hbe8629c79ca22162E+0x1dc>

00000000802018de <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE>:
802018de: 711d         	addi	sp, sp, -0x60
802018e0: ec86         	sd	ra, 0x58(sp)
802018e2: e8a2         	sd	s0, 0x50(sp)
802018e4: e4a6         	sd	s1, 0x48(sp)
802018e6: e0ca         	sd	s2, 0x40(sp)
802018e8: fc4e         	sd	s3, 0x38(sp)
802018ea: f852         	sd	s4, 0x30(sp)
802018ec: f456         	sd	s5, 0x28(sp)
802018ee: f05a         	sd	s6, 0x20(sp)
802018f0: ec5e         	sd	s7, 0x18(sp)
802018f2: e862         	sd	s8, 0x10(sp)
802018f4: e466         	sd	s9, 0x8(sp)
802018f6: e06a         	sd	s10, 0x0(sp)
802018f8: 1080         	addi	s0, sp, 0x60
802018fa: 89b2         	mv	s3, a2
802018fc: 01056483     	lwu	s1, 0x10(a0)
80201900: 18000637     	lui	a2, 0x18000
80201904: 8e65         	and	a2, a2, s1
80201906: 892e         	mv	s2, a1
80201908: ce45         	beqz	a2, 0x802019c0 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xe2>
8020190a: 02349593     	slli	a1, s1, 0x23
8020190e: 0405c863     	bltz	a1, 0x8020195e <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x80>
80201912: 02000593     	li	a1, 0x20
80201916: 0cb9f863     	bgeu	s3, a1, 0x802019e6 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x108>
8020191a: 4581         	li	a1, 0x0
8020191c: 00098f63     	beqz	s3, 0x8020193a <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x5c>
80201920: 01390633     	add	a2, s2, s3
80201924: 86ca         	mv	a3, s2
80201926: 00068703     	lb	a4, 0x0(a3)
8020192a: 0685         	addi	a3, a3, 0x1
8020192c: fc072713     	slti	a4, a4, -0x40
80201930: 00174713     	xori	a4, a4, 0x1
80201934: 95ba         	add	a1, a1, a4
80201936: fec698e3     	bne	a3, a2, 0x80201926 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x48>
8020193a: 01455603     	lhu	a2, 0x14(a0)
8020193e: 08c5f163     	bgeu	a1, a2, 0x802019c0 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xe2>
80201942: 4b81         	li	s7, 0x0
80201944: 40b60b33     	sub	s6, a2, a1
80201948: 02149613     	slli	a2, s1, 0x21
8020194c: 9279         	srli	a2, a2, 0x3e
8020194e: 4685         	li	a3, 0x1
80201950: 02b49593     	slli	a1, s1, 0x2b
80201954: 0ac6c763     	blt	a3, a2, 0x80201a02 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x124>
80201958: ce45         	beqz	a2, 0x80201a10 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x132>
8020195a: 8bda         	mv	s7, s6
8020195c: a855         	j	0x80201a10 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x132>
8020195e: 01655583     	lhu	a1, 0x16(a0)
80201962: 10058563     	beqz	a1, 0x80201a6c <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x18e>
80201966: 013906b3     	add	a3, s2, s3
8020196a: 0e000893     	li	a7, 0xe0
8020196e: 0f000813     	li	a6, 0xf0
80201972: 87ca         	mv	a5, s2
80201974: 862e         	mv	a2, a1
80201976: 4981         	li	s3, 0x0
80201978: a811         	j	0x8020198c <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xae>
8020197a: 00178713     	addi	a4, a5, 0x1
8020197e: 413787b3     	sub	a5, a5, s3
80201982: 167d         	addi	a2, a2, -0x1
80201984: 40f709b3     	sub	s3, a4, a5
80201988: 87ba         	mv	a5, a4
8020198a: c615         	beqz	a2, 0x802019b6 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xd8>
8020198c: 02d78563     	beq	a5, a3, 0x802019b6 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xd8>
80201990: 00078703     	lb	a4, 0x0(a5)
80201994: fe0753e3     	bgez	a4, 0x8020197a <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x9c>
80201998: 0ff77713     	zext.b	a4, a4
8020199c: 01176763     	bltu	a4, a7, 0x802019aa <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xcc>
802019a0: 01076863     	bltu	a4, a6, 0x802019b0 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xd2>
802019a4: 00478713     	addi	a4, a5, 0x4
802019a8: bfd9         	j	0x8020197e <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xa0>
802019aa: 00278713     	addi	a4, a5, 0x2
802019ae: bfc1         	j	0x8020197e <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xa0>
802019b0: 00378713     	addi	a4, a5, 0x3
802019b4: b7e9         	j	0x8020197e <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xa0>
802019b6: 8d91         	sub	a1, a1, a2
802019b8: 01455603     	lhu	a2, 0x14(a0)
802019bc: f8c5e3e3     	bltu	a1, a2, 0x80201942 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x64>
802019c0: 650c         	ld	a1, 0x8(a0)
802019c2: 6108         	ld	a0, 0x0(a0)
802019c4: 6d9c         	ld	a5, 0x18(a1)
802019c6: 85ca         	mv	a1, s2
802019c8: 864e         	mv	a2, s3
802019ca: 60e6         	ld	ra, 0x58(sp)
802019cc: 6446         	ld	s0, 0x50(sp)
802019ce: 64a6         	ld	s1, 0x48(sp)
802019d0: 6906         	ld	s2, 0x40(sp)
802019d2: 79e2         	ld	s3, 0x38(sp)
802019d4: 7a42         	ld	s4, 0x30(sp)
802019d6: 7aa2         	ld	s5, 0x28(sp)
802019d8: 7b02         	ld	s6, 0x20(sp)
802019da: 6be2         	ld	s7, 0x18(sp)
802019dc: 6c42         	ld	s8, 0x10(sp)
802019de: 6ca2         	ld	s9, 0x8(sp)
802019e0: 6d02         	ld	s10, 0x0(sp)
802019e2: 6125         	addi	sp, sp, 0x60
802019e4: 8782         	jr	a5
802019e6: 8a2a         	mv	s4, a0
802019e8: 854a         	mv	a0, s2
802019ea: 85ce         	mv	a1, s3
802019ec: 00000097     	auipc	ra, 0x0
802019f0: 0be080e7     	jalr	0xbe(ra) <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E>
802019f4: 85aa         	mv	a1, a0
802019f6: 8552         	mv	a0, s4
802019f8: 014a5603     	lhu	a2, 0x14(s4)
802019fc: fcc5f2e3     	bgeu	a1, a2, 0x802019c0 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xe2>
80201a00: b789         	j	0x80201942 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x64>
80201a02: 4689         	li	a3, 0x2
80201a04: 00d61663     	bne	a2, a3, 0x80201a10 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x132>
80201a08: 030b1613     	slli	a2, s6, 0x30
80201a0c: 03165b93     	srli	s7, a2, 0x31
80201a10: 4481         	li	s1, 0x0
80201a12: 02b5da13     	srli	s4, a1, 0x2b
80201a16: 00053a83     	ld	s5, 0x0(a0)
80201a1a: 00853c03     	ld	s8, 0x8(a0)
80201a1e: 6cc1         	lui	s9, 0x10
80201a20: 1cfd         	addi	s9, s9, -0x1
80201a22: 019bfd33     	and	s10, s7, s9
80201a26: 0194f533     	and	a0, s1, s9
80201a2a: 01a57a63     	bgeu	a0, s10, 0x80201a3e <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x160>
80201a2e: 020c3603     	ld	a2, 0x20(s8)
80201a32: 0485         	addi	s1, s1, 0x1
80201a34: 8556         	mv	a0, s5
80201a36: 85d2         	mv	a1, s4
80201a38: 9602         	jalr	a2
80201a3a: d575         	beqz	a0, 0x80201a26 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x148>
80201a3c: a801         	j	0x80201a4c <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x16e>
80201a3e: 018c3683     	ld	a3, 0x18(s8)
80201a42: 8556         	mv	a0, s5
80201a44: 85ca         	mv	a1, s2
80201a46: 864e         	mv	a2, s3
80201a48: 9682         	jalr	a3
80201a4a: c51d         	beqz	a0, 0x80201a78 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x19a>
80201a4c: 4905         	li	s2, 0x1
80201a4e: 854a         	mv	a0, s2
80201a50: 60e6         	ld	ra, 0x58(sp)
80201a52: 6446         	ld	s0, 0x50(sp)
80201a54: 64a6         	ld	s1, 0x48(sp)
80201a56: 6906         	ld	s2, 0x40(sp)
80201a58: 79e2         	ld	s3, 0x38(sp)
80201a5a: 7a42         	ld	s4, 0x30(sp)
80201a5c: 7aa2         	ld	s5, 0x28(sp)
80201a5e: 7b02         	ld	s6, 0x20(sp)
80201a60: 6be2         	ld	s7, 0x18(sp)
80201a62: 6c42         	ld	s8, 0x10(sp)
80201a64: 6ca2         	ld	s9, 0x8(sp)
80201a66: 6d02         	ld	s10, 0x0(sp)
80201a68: 6125         	addi	sp, sp, 0x60
80201a6a: 8082         	ret
80201a6c: 4981         	li	s3, 0x0
80201a6e: 01455603     	lhu	a2, 0x14(a0)
80201a72: ecc5e8e3     	bltu	a1, a2, 0x80201942 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x64>
80201a76: b7a9         	j	0x802019c0 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0xe2>
80201a78: 4481         	li	s1, 0x0
80201a7a: 417b0533     	sub	a0, s6, s7
80201a7e: 69c1         	lui	s3, 0x10
80201a80: 19fd         	addi	s3, s3, -0x1
80201a82: 01357b33     	and	s6, a0, s3
80201a86: 0134f533     	and	a0, s1, s3
80201a8a: 01653933     	sltu	s2, a0, s6
80201a8e: fd6570e3     	bgeu	a0, s6, 0x80201a4e <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x170>
80201a92: 020c3603     	ld	a2, 0x20(s8)
80201a96: 0485         	addi	s1, s1, 0x1
80201a98: 8556         	mv	a0, s5
80201a9a: 85d2         	mv	a1, s4
80201a9c: 9602         	jalr	a2
80201a9e: d565         	beqz	a0, 0x80201a86 <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x1a8>
80201aa0: b77d         	j	0x80201a4e <_ZN4core3fmt9Formatter3pad17h4da36f4a8944936eE+0x170>

0000000080201aa2 <_ZN57_$LT$core..fmt..Formatter$u20$as$u20$core..fmt..Write$GT$9write_str17h49dd41e699fcd1f7E>:
80201aa2: 6514         	ld	a3, 0x8(a0)
80201aa4: 6108         	ld	a0, 0x0(a0)
80201aa6: 6e9c         	ld	a5, 0x18(a3)
80201aa8: 8782         	jr	a5

0000000080201aaa <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E>:
80201aaa: 1141         	addi	sp, sp, -0x10
80201aac: e422         	sd	s0, 0x8(sp)
80201aae: e026         	sd	s1, 0x0(sp)
80201ab0: 862a         	mv	a2, a0
80201ab2: 00750713     	addi	a4, a0, 0x7
80201ab6: 9b61         	andi	a4, a4, -0x8
80201ab8: 40a702b3     	sub	t0, a4, a0
80201abc: 0255f363     	bgeu	a1, t0, 0x80201ae2 <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0x38>
80201ac0: 4501         	li	a0, 0x0
80201ac2: cd81         	beqz	a1, 0x80201ada <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0x30>
80201ac4: 95b2         	add	a1, a1, a2
80201ac6: 00060683     	lb	a3, 0x0(a2)
80201aca: 0605         	addi	a2, a2, 0x1
80201acc: fc06a693     	slti	a3, a3, -0x40
80201ad0: 0016c693     	xori	a3, a3, 0x1
80201ad4: 9536         	add	a0, a0, a3
80201ad6: feb618e3     	bne	a2, a1, 0x80201ac6 <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0x1c>
80201ada: 6422         	ld	s0, 0x8(sp)
80201adc: 6482         	ld	s1, 0x0(sp)
80201ade: 0141         	addi	sp, sp, 0x10
80201ae0: 8082         	ret
80201ae2: 40558833     	sub	a6, a1, t0
80201ae6: 00385e13     	srli	t3, a6, 0x3
80201aea: fc0e0be3     	beqz	t3, 0x80201ac0 <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0x16>
80201aee: 92b2         	add	t0, t0, a2
80201af0: 00787893     	andi	a7, a6, 0x7
80201af4: 4501         	li	a0, 0x0
80201af6: 00c70c63     	beq	a4, a2, 0x80201b0e <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0x64>
80201afa: 00060583     	lb	a1, 0x0(a2)
80201afe: 0605         	addi	a2, a2, 0x1
80201b00: fc05a593     	slti	a1, a1, -0x40
80201b04: 0015c593     	xori	a1, a1, 0x1
80201b08: 952e         	add	a0, a0, a1
80201b0a: fe5618e3     	bne	a2, t0, 0x80201afa <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0x50>
80201b0e: 4581         	li	a1, 0x0
80201b10: 02088163     	beqz	a7, 0x80201b32 <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0x88>
80201b14: ff887613     	andi	a2, a6, -0x8
80201b18: 9732         	add	a4, a4, a2
80201b1a: 9616         	add	a2, a2, t0
80201b1c: 98ba         	add	a7, a7, a4
80201b1e: 00060703     	lb	a4, 0x0(a2)
80201b22: 0605         	addi	a2, a2, 0x1
80201b24: fc072713     	slti	a4, a4, -0x40
80201b28: 00174713     	xori	a4, a4, 0x1
80201b2c: 95ba         	add	a1, a1, a4
80201b2e: ff1618e3     	bne	a2, a7, 0x80201b1e <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0x74>
80201b32: 01010637     	lui	a2, 0x1010
80201b36: 00ff0737     	lui	a4, 0xff0
80201b3a: 67c1         	lui	a5, 0x10
80201b3c: 10160613     	addi	a2, a2, 0x101
80201b40: 0ff70893     	addi	a7, a4, 0xff
80201b44: 0785         	addi	a5, a5, 0x1
80201b46: 02061713     	slli	a4, a2, 0x20
80201b4a: 00e60eb3     	add	t4, a2, a4
80201b4e: 02089613     	slli	a2, a7, 0x20
80201b52: 98b2         	add	a7, a7, a2
80201b54: 02079813     	slli	a6, a5, 0x20
80201b58: 983e         	add	a6, a6, a5
80201b5a: 952e         	add	a0, a0, a1
80201b5c: a015         	j	0x80201b80 <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0xd6>
80201b5e: 929a         	add	t0, t0, t1
80201b60: 407e0e33     	sub	t3, t3, t2
80201b64: 0033f793     	andi	a5, t2, 0x3
80201b68: 011f75b3     	and	a1, t5, a7
80201b6c: 008f5613     	srli	a2, t5, 0x8
80201b70: 01167633     	and	a2, a2, a7
80201b74: 95b2         	add	a1, a1, a2
80201b76: 030585b3     	mul	a1, a1, a6
80201b7a: 91c1         	srli	a1, a1, 0x30
80201b7c: 952e         	add	a0, a0, a1
80201b7e: efad         	bnez	a5, 0x80201bf8 <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0x14e>
80201b80: f40e0de3     	beqz	t3, 0x80201ada <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0x30>
80201b84: 8316         	mv	t1, t0
80201b86: 0c000593     	li	a1, 0xc0
80201b8a: 83f2         	mv	t2, t3
80201b8c: 00be6463     	bltu	t3, a1, 0x80201b94 <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0xea>
80201b90: 0c000393     	li	t2, 0xc0
80201b94: 00339293     	slli	t0, t2, 0x3
80201b98: 4f01         	li	t5, 0x0
80201b9a: 7e02f793     	andi	a5, t0, 0x7e0
80201b9e: d3e1         	beqz	a5, 0x80201b5e <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0xb4>
80201ba0: 859a         	mv	a1, t1
80201ba2: 0005bf83     	ld	t6, 0x0(a1)
80201ba6: 6584         	ld	s1, 0x8(a1)
80201ba8: 6990         	ld	a2, 0x10(a1)
80201baa: 6d94         	ld	a3, 0x18(a1)
80201bac: ffffc413     	not	s0, t6
80201bb0: 006fd713     	srli	a4, t6, 0x6
80201bb4: 801d         	srli	s0, s0, 0x7
80201bb6: 8f41         	or	a4, a4, s0
80201bb8: fff4c413     	not	s0, s1
80201bbc: 8099         	srli	s1, s1, 0x6
80201bbe: 801d         	srli	s0, s0, 0x7
80201bc0: 8c45         	or	s0, s0, s1
80201bc2: fff64493     	not	s1, a2
80201bc6: 8219         	srli	a2, a2, 0x6
80201bc8: 809d         	srli	s1, s1, 0x7
80201bca: 8e45         	or	a2, a2, s1
80201bcc: fff6c493     	not	s1, a3
80201bd0: 8299         	srli	a3, a3, 0x6
80201bd2: 809d         	srli	s1, s1, 0x7
80201bd4: 8ec5         	or	a3, a3, s1
80201bd6: 01d77733     	and	a4, a4, t4
80201bda: 977a         	add	a4, a4, t5
80201bdc: 1781         	addi	a5, a5, -0x20
80201bde: 01d474b3     	and	s1, s0, t4
80201be2: 01d67633     	and	a2, a2, t4
80201be6: 01d6ff33     	and	t5, a3, t4
80201bea: 9626         	add	a2, a2, s1
80201bec: 963a         	add	a2, a2, a4
80201bee: 9f32         	add	t5, t5, a2
80201bf0: 02058593     	addi	a1, a1, 0x20
80201bf4: f7dd         	bnez	a5, 0x80201ba2 <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0xf8>
80201bf6: b7a5         	j	0x80201b5e <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0xb4>
80201bf8: 4581         	li	a1, 0x0
80201bfa: 0fc3f613     	andi	a2, t2, 0xfc
80201bfe: 060e         	slli	a2, a2, 0x3
80201c00: 9332         	add	t1, t1, a2
80201c02: 00379613     	slli	a2, a5, 0x3
80201c06: 00033683     	ld	a3, 0x0(t1)
80201c0a: 0321         	addi	t1, t1, 0x8
80201c0c: fff6c713     	not	a4, a3
80201c10: 8299         	srli	a3, a3, 0x6
80201c12: 831d         	srli	a4, a4, 0x7
80201c14: 8ed9         	or	a3, a3, a4
80201c16: 01d6f6b3     	and	a3, a3, t4
80201c1a: 1661         	addi	a2, a2, -0x8
80201c1c: 95b6         	add	a1, a1, a3
80201c1e: f665         	bnez	a2, 0x80201c06 <_ZN4core3str5count14do_count_chars17h3795b1e3ab26ed97E+0x15c>
80201c20: 0115f633     	and	a2, a1, a7
80201c24: 81a1         	srli	a1, a1, 0x8
80201c26: 0115f5b3     	and	a1, a1, a7
80201c2a: 95b2         	add	a1, a1, a2
80201c2c: 030585b3     	mul	a1, a1, a6
80201c30: 91c1         	srli	a1, a1, 0x30
80201c32: 952e         	add	a0, a0, a1
80201c34: 6422         	ld	s0, 0x8(sp)
80201c36: 6482         	ld	s1, 0x0(sp)
80201c38: 0141         	addi	sp, sp, 0x10
80201c3a: 8082         	ret

0000000080201c3c <_ZN4core6result13unwrap_failed17h5e3f8b6846658e00E>:
80201c3c: 7119         	addi	sp, sp, -0x80
80201c3e: fc86         	sd	ra, 0x78(sp)
80201c40: f8a2         	sd	s0, 0x70(sp)
80201c42: 0100         	addi	s0, sp, 0x80
80201c44: f8a43023     	sd	a0, -0x80(s0)
80201c48: f8b43423     	sd	a1, -0x78(s0)
80201c4c: f8c43823     	sd	a2, -0x70(s0)
80201c50: f8d43c23     	sd	a3, -0x68(s0)
80201c54: f8040813     	addi	a6, s0, -0x80

0000000080201c58 <.Lpcrel_hi919>:
80201c58: fffff597     	auipc	a1, 0xfffff
80201c5c: f9040893     	addi	a7, s0, -0x70

0000000080201c60 <.Lpcrel_hi920>:
80201c60: fffff697     	auipc	a3, 0xfffff

0000000080201c64 <.Lpcrel_hi921>:
80201c64: 00000797     	auipc	a5, 0x0
80201c68: 4509         	li	a0, 0x2
80201c6a: fc043023     	sd	zero, -0x40(s0)
80201c6e: fd040613     	addi	a2, s0, -0x30
80201c72: 6f858593     	addi	a1, a1, 0x6f8
80201c76: 6e868693     	addi	a3, a3, 0x6e8
80201c7a: 60478793     	addi	a5, a5, 0x604
80201c7e: fd043823     	sd	a6, -0x30(s0)
80201c82: fcb43c23     	sd	a1, -0x28(s0)
80201c86: ff143023     	sd	a7, -0x20(s0)
80201c8a: fed43423     	sd	a3, -0x18(s0)
80201c8e: faf43023     	sd	a5, -0x60(s0)
80201c92: faa43423     	sd	a0, -0x58(s0)
80201c96: fac43823     	sd	a2, -0x50(s0)
80201c9a: faa43c23     	sd	a0, -0x48(s0)
80201c9e: fa040513     	addi	a0, s0, -0x60
80201ca2: 85ba         	mv	a1, a4
80201ca4: 00000097     	auipc	ra, 0x0
80201ca8: 008080e7     	jalr	0x8(ra) <_ZN4core9panicking9panic_fmt17hd981144b4a491ec5E>

0000000080201cac <_ZN4core9panicking9panic_fmt17hd981144b4a491ec5E>:
80201cac: 7179         	addi	sp, sp, -0x30
80201cae: f406         	sd	ra, 0x28(sp)
80201cb0: f022         	sd	s0, 0x20(sp)
80201cb2: 1800         	addi	s0, sp, 0x30
80201cb4: 4605         	li	a2, 0x1
80201cb6: fca43c23     	sd	a0, -0x28(s0)
80201cba: feb43023     	sd	a1, -0x20(s0)
80201cbe: fec41423     	sh	a2, -0x18(s0)
80201cc2: fd840513     	addi	a0, s0, -0x28
80201cc6: fffff097     	auipc	ra, 0xfffff
80201cca: 33a080e7     	jalr	0x33a(ra) <strampoline>

0000000080201cce <_ZN73_$LT$core..panic..panic_info..PanicInfo$u20$as$u20$core..fmt..Display$GT$3fmt17h5ff76826d4c971f1E>:
80201cce: 7171         	addi	sp, sp, -0xb0
80201cd0: f506         	sd	ra, 0xa8(sp)
80201cd2: f122         	sd	s0, 0xa0(sp)
80201cd4: ed26         	sd	s1, 0x98(sp)
80201cd6: e94a         	sd	s2, 0x90(sp)
80201cd8: e54e         	sd	s3, 0x88(sp)
80201cda: e152         	sd	s4, 0x80(sp)
80201cdc: fcd6         	sd	s5, 0x78(sp)
80201cde: 1900         	addi	s0, sp, 0xb0
80201ce0: 0085b903     	ld	s2, 0x8(a1)
80201ce4: 6184         	ld	s1, 0x0(a1)
80201ce6: 01893a83     	ld	s5, 0x18(s2)
80201cea: 89aa         	mv	s3, a0

0000000080201cec <.Lpcrel_hi1269>:
80201cec: 00000517     	auipc	a0, 0x0
80201cf0: 5d450593     	addi	a1, a0, 0x5d4
80201cf4: 4631         	li	a2, 0xc
80201cf6: 8526         	mv	a0, s1
80201cf8: 9a82         	jalr	s5
80201cfa: 4a05         	li	s4, 0x1
80201cfc: e169         	bnez	a0, 0x80201dbe <.Lpcrel_hi1273+0x4a>
80201cfe: 0089b503     	ld	a0, 0x8(s3)
80201d02: f8840813     	addi	a6, s0, -0x78

0000000080201d06 <.Lpcrel_hi1270>:
80201d06: fffff617     	auipc	a2, 0xfffff

0000000080201d0a <.Lpcrel_hi1271>:
80201d0a: fffff697     	auipc	a3, 0xfffff

0000000080201d0e <.Lpcrel_hi1272>:
80201d0e: 00000897     	auipc	a7, 0x0
80201d12: 64a60613     	addi	a2, a2, 0x64a
80201d16: 65668693     	addi	a3, a3, 0x656
80201d1a: 611c         	ld	a5, 0x0(a0)
80201d1c: 650c         	ld	a1, 0x8(a0)
80201d1e: 01050713     	addi	a4, a0, 0x10
80201d22: 0551         	addi	a0, a0, 0x14
80201d24: f9043c23     	sd	a6, -0x68(s0)
80201d28: fac43023     	sd	a2, -0x60(s0)
80201d2c: fae43423     	sd	a4, -0x58(s0)
80201d30: fad43823     	sd	a3, -0x50(s0)
80201d34: faa43c23     	sd	a0, -0x48(s0)
80201d38: fcd43023     	sd	a3, -0x40(s0)
80201d3c: 450d         	li	a0, 0x3
80201d3e: f6043c23     	sd	zero, -0x88(s0)
80201d42: f8f43423     	sd	a5, -0x78(s0)
80201d46: f8b43823     	sd	a1, -0x70(s0)
80201d4a: f9840593     	addi	a1, s0, -0x68
80201d4e: 58288613     	addi	a2, a7, 0x582
80201d52: f4c43c23     	sd	a2, -0xa8(s0)
80201d56: f6a43023     	sd	a0, -0xa0(s0)
80201d5a: f6b43423     	sd	a1, -0x98(s0)
80201d5e: f6a43823     	sd	a0, -0x90(s0)
80201d62: f5840613     	addi	a2, s0, -0xa8
80201d66: 8526         	mv	a0, s1
80201d68: 85ca         	mv	a1, s2
80201d6a: fffff097     	auipc	ra, 0xfffff
80201d6e: 730080e7     	jalr	0x730(ra) <_ZN4core3fmt5write17h88f98981b8a86a90E>
80201d72: e531         	bnez	a0, 0x80201dbe <.Lpcrel_hi1273+0x4a>

0000000080201d74 <.Lpcrel_hi1273>:
80201d74: 00000517     	auipc	a0, 0x0
80201d78: 55850593     	addi	a1, a0, 0x558
80201d7c: 4609         	li	a2, 0x2
80201d7e: 8526         	mv	a0, s1
80201d80: 9a82         	jalr	s5
80201d82: ed15         	bnez	a0, 0x80201dbe <.Lpcrel_hi1273+0x4a>
80201d84: 0009b503     	ld	a0, 0x0(s3)
80201d88: 610c         	ld	a1, 0x0(a0)
80201d8a: f8b43c23     	sd	a1, -0x68(s0)
80201d8e: 650c         	ld	a1, 0x8(a0)
80201d90: fab43023     	sd	a1, -0x60(s0)
80201d94: 690c         	ld	a1, 0x10(a0)
80201d96: fab43423     	sd	a1, -0x58(s0)
80201d9a: 6d0c         	ld	a1, 0x18(a0)
80201d9c: fab43823     	sd	a1, -0x50(s0)
80201da0: 710c         	ld	a1, 0x20(a0)
80201da2: fab43c23     	sd	a1, -0x48(s0)
80201da6: 7508         	ld	a0, 0x28(a0)
80201da8: fca43023     	sd	a0, -0x40(s0)
80201dac: f9840613     	addi	a2, s0, -0x68
80201db0: 8526         	mv	a0, s1
80201db2: 85ca         	mv	a1, s2
80201db4: fffff097     	auipc	ra, 0xfffff
80201db8: 6e6080e7     	jalr	0x6e6(ra) <_ZN4core3fmt5write17h88f98981b8a86a90E>
80201dbc: 8a2a         	mv	s4, a0
80201dbe: 8552         	mv	a0, s4
80201dc0: 70aa         	ld	ra, 0xa8(sp)
80201dc2: 740a         	ld	s0, 0xa0(sp)
80201dc4: 64ea         	ld	s1, 0x98(sp)
80201dc6: 694a         	ld	s2, 0x90(sp)
80201dc8: 69aa         	ld	s3, 0x88(sp)
80201dca: 6a0a         	ld	s4, 0x80(sp)
80201dcc: 7ae6         	ld	s5, 0x78(sp)
80201dce: 614d         	addi	sp, sp, 0xb0
80201dd0: 8082         	ret
