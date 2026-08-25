package bridge

import (
	"context"
	cryptorand "crypto/rand"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"

	zk "github.com/gagliardetto/solana-go/programs/zk-elgamal-proof"
)

// Solana-zk-sdk Rust prover compiled to wasm32.
//
//go:embed solana_zk_sdk_wasm.wasm
var bridgeWasm []byte

var poolSize = runtime.NumCPU()

const ALLOC_FUNC = "zk_alloc"
const FREE_FUNC = "zk_free"

var (
	initOnce     sync.Once
	initErr      error
	wasmRuntime  wazero.Runtime
	wasmCompiled wazero.CompiledModule
	// instancePool holds poolSize wasm instances, each initialised to nil
	instancePool = make(chan api.Module, poolSize)
)

// init seeds the pool with poolSize nil instances
func init() {
	for i := 0; i < poolSize; i++ {
		instancePool <- nil
	}
}

func initWasmRuntime() {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, rt); err != nil {
		rt.Close(ctx)
		initErr = fmt.Errorf("zk: instantiating WASI host module: %w", err)
		return
	}
	compiled, err := rt.CompileModule(ctx, bridgeWasm)
	if err != nil {
		rt.Close(ctx)
		initErr = fmt.Errorf("zk: compiling bridge module: %w", err)
		return
	}
	wasmRuntime = rt
	wasmCompiled = compiled
}

// acquireInstance takes slot from pool, instantiating slot if nil.
func acquireInstance() (api.Module, error) {
	initOnce.Do(initWasmRuntime)
	if initErr != nil {
		return nil, initErr
	}
	if inst := <-instancePool; inst != nil {
		// Use instantiated instance from pool.
		return inst, nil
	}
	// Empty slot: build a new instance.
	inst, err := initInstance()
	if err != nil {
		instancePool <- nil
		return nil, err
	}
	return inst, nil
}

// releaseInstance hands the slot back to the pool.
func releaseInstance(inst api.Module) {
	instancePool <- inst
}

func initInstance() (mod api.Module, err error) {
	ctx := context.Background()

	// Configure as anonymous library module.
	cfg := wazero.NewModuleConfig().
		WithName("").
		WithStartFunctions().             // WASI reactor: suppress _start
		WithRandSource(cryptorand.Reader) // Randomness source must be set explicitly, wazero's default uses fixed seed
	mod, err = wasmRuntime.InstantiateModule(ctx, wasmCompiled, cfg)
	if err != nil {
		return nil, fmt.Errorf("zk: instantiating bridge module: %w", err)
	}
	// Any validation failure must close the instantiated module.
	defer func() {
		if err != nil {
			mod.Close(ctx)
			mod = nil
		}
	}()

	// Run the guest program's _initialize function.
	if initFn := mod.ExportedFunction("_initialize"); initFn != nil {
		if _, err = initFn.Call(ctx); err != nil {
			return mod, fmt.Errorf("zk: running module _initialize: %w", err)
		}
	}
	// Make sure that expected memory functions are exported by the WASM ABI
	for _, name := range []string{ALLOC_FUNC, FREE_FUNC} {
		if mod.ExportedFunction(name) == nil {
			return mod, fmt.Errorf("zk: required export %q not found", name)
		}
	}
	return mod, nil
}

// span is one guest allocation owned by a frame.
type span struct {
	ptr, size uint32
}

// frame controls the memory allocations of a single bridge call.
type frame struct {
	inst     api.Module
	allocs   []span
	poisoned bool
}

// acquire binds the frame to a pooled instance, blocking until a free-slot is available.
func (f *frame) acquire() error {
	inst, err := acquireInstance()
	if err != nil {
		return err
	}
	f.inst = inst
	return nil
}

// release scrubs and frees the call's guest allocations and returns the
// instance to the pool, or closes the instance if poisoned.
func (f *frame) release() {
	if !f.poisoned {
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
	if f.poisoned {
		f.inst.Close(context.Background())
		f.inst = nil
	}
	releaseInstance(f.inst)
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

// InvokeWith borrows an instance, marshals parts into export arguments, calls the named export,
// and copies out its result.
func InvokeWith(name string, parts ...any) ([]byte, error) {
	f := &frame{}
	if err := f.acquire(); err != nil {
		return nil, err
	}
	defer f.release()

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

// InvokeStatus is InvokeWith for exports that return only a status code.
func InvokeStatus(name string, parts ...any) error {
	_, err := InvokeWith(name, parts...)
	return err
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
