package bridge

import (
	"context"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/tetratelabs/wazero/api"

	zk "github.com/gagliardetto/solana-go/programs/zk-elgamal-proof"
)

// InvokeStatus is InvokeWith for exports that return only a status code.
func InvokeStatus(name string, parts ...any) error {
	_, err := InvokeWith(name, parts...)
	return err
}

// InvokeWith borrows an instance, marshals parts into export arguments, calls the named export,
// and copies out its result.
func InvokeWith(name string, parts ...any) ([]byte, error) {
	f := &frame{}
	if err := f.acquireInstance(); err != nil {
		return nil, err
	}
	defer f.releaseInstance()

	args, err := buildArgs(f, parts...)
	if err != nil {
		return nil, err
	}

	fn := f.inst.ExportedFunction(name)
	if fn == nil {
		return nil, fmt.Errorf("zk: bridge export %q not found", name)
	}
	res, err := fn.Call(context.Background(), args...)
	if err != nil {
		f.poisoned = true
		return nil, fmt.Errorf("zk: calling %s: %w", name, err)
	}
	if len(res) != 1 {
		return nil, fmt.Errorf("zk: %s returned %d results, want 1", name, len(res))
	}
	return f.decodeResult(fn, res[0])
}

// CopyOut copies a guest result into dst, rejecting results whose length does
// not match exactly.
func CopyOut(dst, out []byte, err error) error {
	if err != nil {
		return err
	}
	if len(out) != len(dst) {
		return fmt.Errorf("zk: guest returned %d bytes, want %d", len(out), len(dst))
	}
	copy(dst, out)
	return nil
}

// Zeroize clears a transient buffer holding secret material.
func Zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// ToAmount decodes a guest result holding a little-endian u64 amount.
func ToAmount(out []byte, err error) (uint64, error) {
	if err != nil {
		return 0, err
	}
	if len(out) != 8 {
		return 0, fmt.Errorf("zk: guest returned %d bytes, want 8", len(out))
	}
	return binary.LittleEndian.Uint64(out), nil
}

// span is one guest allocation owned by a frame.
type span struct {
	ptr, size uint32
}

// frame controls the memory allocations of a single wasm call.
type frame struct {
	inst     api.Module
	allocs   []span
	poisoned bool
}

// acquireInstance binds the frame to a pooled instance, blocking until a free-slot is available.
func (f *frame) acquireInstance() error {
	inst, err := getInstance()
	if err != nil {
		return err
	}
	f.inst = inst
	return nil
}

// releaseInstance releases the call's module instance back to the pool.
func (f *frame) releaseInstance() {
	if !f.poisoned {
		// Return initialized instance to pool, scrub and free memory first.
		f.scrubAndFreeMemory()
	}
	if f.poisoned {
		// Close the instance, feed nil slot to pool.
		f.inst.Close(context.Background())
		f.inst = nil
	}
	returnInstance(f.inst)
}

func (f *frame) scrubAndFreeMemory() {
	free := f.inst.ExportedFunction(FREE_FUNC)
	ctx := context.Background()
	var zeros []byte
	for _, a := range f.allocs {
		if int(a.size) > len(zeros) {
			zeros = make([]byte, a.size)
		}
		f.inst.Memory().Write(a.ptr, zeros[:a.size])
		if _, err := free.Call(ctx, uint64(a.ptr)); err != nil {
			f.poisoned = true
			break
		}
	}
}

// write copies b into guest memory and returns the guest pointer.
func (f *frame) write(b []byte) (uint64, error) {
	if len(b) == 0 {
		return 0, errors.New("zk: attempted to write empty buffer")
	}
	res, err := f.inst.ExportedFunction(ALLOC_FUNC).Call(context.Background(), uint64(len(b)))
	if err != nil {
		f.poisoned = true
		return 0, fmt.Errorf("zk: guest alloc: %w", err)
	}
	if len(res) != 1 {
		return 0, fmt.Errorf("zk: zk_alloc returned %d results, want 1", len(res))
	}
	// zk_alloc returns 0 to signal allocation failure
	ptr := uint32(res[0])
	if ptr == 0 {
		return 0, zk.Error(zk.OOM)
	}
	f.allocs = append(f.allocs, span{ptr, uint32(len(b))})
	if !f.inst.Memory().Write(ptr, b) {
		return 0, errors.New("zk: guest memory write out of range")
	}
	return uint64(ptr), nil
}

// decodeResult interprets an export's single return value by its declared
// result type.
func (f *frame) decodeResult(fn api.Function, raw uint64) ([]byte, error) {
	if fn.Definition().ResultTypes()[0] == api.ValueTypeI32 {
		if status := int32(uint32(raw)); status != zk.OK {
			return nil, zk.Error(status)
		}
		return nil, nil
	}
	packed := int64(raw)
	if packed < 0 {
		return nil, zk.Error(int32(packed))
	}
	if packed == 0 {
		return nil, nil
	}
	ptr, length := uint32(packed), uint32(packed>>32)
	f.allocs = append(f.allocs, span{ptr, length})
	view, ok := f.inst.Memory().Read(ptr, length)
	if !ok {
		return nil, errors.New("zk: guest memory read out of range")
	}
	out := make([]byte, length)
	copy(out, view)
	return out, nil
}

// buildArgs writes each []byte part into guest memory (appending its pointer
// to the argument list) and passes uint64 parts through as-is, preserving
// order.
func buildArgs(f *frame, parts ...any) ([]uint64, error) {
	args := make([]uint64, 0, len(parts))
	for _, part := range parts {
		switch v := part.(type) {
		case []byte:
			ptr, err := f.write(v)
			if err != nil {
				return nil, err
			}
			args = append(args, ptr)
		case uint64:
			args = append(args, v)
		default:
			return nil, fmt.Errorf("zk: unsupported argument type %T", part)
		}
	}
	return args, nil
}
