package engine

import (
	"os"
	"testing"
)

func BenchmarkScanJuiceShop(b *testing.B) {
	path := os.Getenv("TS_BENCH_ZIP")
	if path == "" {
		b.Skip("TS_BENCH_ZIP not set")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		b.Fatal(err)
	}
	files, err := FilesFromZip(data, 0, 0, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Scan(files, Options{})
	}
}
