package amd

import (
	"fmt"
	"net/url"
	"strconv"
)

// TCB is a REPORTED_TCB value split into the security patch levels (SPL)
// that KDS addresses a VCEK by. Its layout differs by product: Turin adds
// the FMC level and moves the others.
type TCB struct {
	Product    string
	Bootloader uint8
	TEE        uint8
	SNP        uint8
	Microcode  uint8
	FMC        uint8 // Turin only
}

// DecomposeTCB splits a raw REPORTED_TCB for product.
func DecomposeTCB(product string, raw uint64) (TCB, error) {
	b := func(shift uint) uint8 { return uint8(raw >> shift) }
	switch product {
	case Milan, Genoa:
		return TCB{Product: product, Bootloader: b(0), TEE: b(8), SNP: b(48), Microcode: b(56)}, nil
	case Turin:
		return TCB{Product: product, FMC: b(0), Bootloader: b(8), TEE: b(16), SNP: b(24), Microcode: b(56)}, nil
	}
	return TCB{}, fmt.Errorf("unknown product %q", product)
}

// Uint64 is the raw REPORTED_TCB value, with the reserved levels zero.
func (t TCB) Uint64() uint64 {
	u := func(v uint8, shift uint) uint64 { return uint64(v) << shift }
	if t.Product == Turin {
		return u(t.FMC, 0) | u(t.Bootloader, 8) | u(t.TEE, 16) | u(t.SNP, 24) | u(t.Microcode, 56)
	}
	return u(t.Bootloader, 0) | u(t.TEE, 8) | u(t.SNP, 48) | u(t.Microcode, 56)
}

// Values are the KDS VCEK query parameters.
func (t TCB) Values() url.Values {
	v := url.Values{}
	if t.Product == Turin {
		v.Set("fmcSPL", strconv.Itoa(int(t.FMC)))
	}
	v.Set("blSPL", strconv.Itoa(int(t.Bootloader)))
	v.Set("teeSPL", strconv.Itoa(int(t.TEE)))
	v.Set("snpSPL", strconv.Itoa(int(t.SNP)))
	v.Set("ucodeSPL", strconv.Itoa(int(t.Microcode)))
	return v
}

func (t TCB) String() string {
	if t.Product == Turin {
		return fmt.Sprintf("0x%016x (fmc %d, bootloader %d, tee %d, snp %d, microcode %d)", t.Uint64(), t.FMC, t.Bootloader, t.TEE, t.SNP, t.Microcode)
	}
	return fmt.Sprintf("0x%016x (bootloader %d, tee %d, snp %d, microcode %d)", t.Uint64(), t.Bootloader, t.TEE, t.SNP, t.Microcode)
}
