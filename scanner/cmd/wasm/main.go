//go:build js && wasm

// WASM entrypoint. Exposes the ThreatScape engine to JavaScript under the
// __threatscape global. Designed to run inside a Web Worker so multi-second
// scans never block the render loop.
package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"

	"threatscape/scanner/engine"
)

func emitProgress(done, total int, path string) {
	cb := js.Global().Get("__threatscapeProgress")
	if cb.Type() == js.TypeFunction {
		cb.Invoke(done, total, path)
	}
}

func resultJSON(report *engine.Report, err error) string {
	if err != nil {
		out, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(out)
	}
	out, jerr := json.Marshal(report)
	if jerr != nil {
		fallback, _ := json.Marshal(map[string]string{"error": jerr.Error()})
		return string(fallback)
	}
	return string(out)
}

func guard(name string, fn func(args []js.Value) string) js.Func {
	return js.FuncOf(func(_ js.Value, args []js.Value) (res any) {
		defer func() {
			if r := recover(); r != nil {
				out, _ := json.Marshal(map[string]string{"error": fmt.Sprintf("%s panicked: %v", name, r)})
				res = string(out)
			}
		}()
		return fn(args)
	})
}

// scanZip(zip: Uint8Array) -> JSON string
func scanZip(args []js.Value) string {
	if len(args) < 1 {
		return resultJSON(nil, fmt.Errorf("scanZip expects (Uint8Array)"))
	}
	buf := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(buf, args[0])
	files, err := engine.FilesFromZip(buf, 0, 0, 0)
	if err != nil {
		return resultJSON(nil, err)
	}
	report := engine.Scan(files, engine.Options{Progress: emitProgress})
	return resultJSON(report, nil)
}

// scanFiles(files: Array<{path: string, data?: Uint8Array, size?: number}>) -> JSON string
func scanFiles(args []js.Value) string {
	if len(args) < 1 {
		return resultJSON(nil, fmt.Errorf("scanFiles expects (Array)"))
	}
	arr := args[0]
	n := arr.Get("length").Int()
	files := make([]engine.InputFile, 0, n)
	for i := 0; i < n; i++ {
		item := arr.Index(i)
		f := engine.InputFile{Path: item.Get("path").String()}
		if data := item.Get("data"); data.Truthy() {
			buf := make([]byte, data.Get("length").Int())
			js.CopyBytesToGo(buf, data)
			f.Data = buf
		} else if size := item.Get("size"); size.Type() == js.TypeNumber {
			f.Size = size.Int()
		}
		files = append(files, f)
	}
	report := engine.Scan(files, engine.Options{Progress: emitProgress})
	return resultJSON(report, nil)
}

func main() {
	api := map[string]any{}
	js.Global().Set("__threatscape", js.ValueOf(api))
	ts := js.Global().Get("__threatscape")
	ts.Set("scanZip", guard("scanZip", scanZip))
	ts.Set("scanFiles", guard("scanFiles", scanFiles))
	ts.Set("version", "1.0.0")
	if cb := js.Global().Get("__threatscapeReady"); cb.Type() == js.TypeFunction {
		cb.Invoke()
	}
	select {} // keep the Go runtime alive for future calls
}
