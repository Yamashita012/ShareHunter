package enumeration

import (
	"context"
	"testing"
	"testing/fstest"
)

func TestWalk(t *testing.T) {
	f := fstest.MapFS{"a.txt": {Data: []byte("x")}, "dir/b.ini": {Data: []byte("y")}}
	files, dirs, errs := Walk(context.Background(), f, Options{MaxDepth: 3, MaxFiles: 10})
	if len(errs) > 0 || len(files) != 2 || dirs != 1 {
		t.Fatalf("files=%d dirs=%d errs=%v", len(files), dirs, errs)
	}
}
