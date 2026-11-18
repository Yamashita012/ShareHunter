package scanner

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/breachoperators/sharehunter/internal/detection"
	"github.com/breachoperators/sharehunter/internal/enumeration"
)

func TestInspectRedactsSecretsAndHonorsLimits(t *testing.T) {
	root := fstest.MapFS{
		"settings.ini": {Data: []byte("db_password=SuperSecret123\n")},
		"notes.bin":    {Data: []byte("password=ignored\n")},
	}
	files, _, errs := enumeration.Walk(context.Background(), root, enumeration.Options{MaxDepth: 2, MaxFiles: 10})
	if len(errs) != 0 {
		t.Fatalf("walk errors: %v", errs)
	}
	findings, inspected := Inspect(context.Background(), root, files, Options{Workers: 2, MaxBytes: 1024, Config: detection.DefaultConfig(), Target: "test", Share: "data"})
	if inspected != 1 {
		t.Fatalf("inspected=%d, want 1", inspected)
	}
	if len(findings) == 0 {
		t.Fatal("expected a finding")
	}
	for _, f := range findings {
		if f.Evidence == "db_password=SuperSecret123" {
			t.Fatal("unredacted secret leaked")
		}
	}
}
