package scanner

import (
	"context"
	"github.com/breachoperators/sharehunter/internal/detection"
	"github.com/breachoperators/sharehunter/internal/enumeration"
	"github.com/breachoperators/sharehunter/internal/reporting"
	"io"
	"io/fs"
	"strings"
	"sync"
	"sync/atomic"
)

type Options struct {
	Workers       int
	MaxBytes      int64
	Config        detection.Config
	Target, Share string
}

func Inspect(ctx context.Context, root fs.FS, files []enumeration.File, o Options) ([]reporting.Finding, int) {
	if o.Workers < 1 {
		o.Workers = 1
	}
	jobs := make(chan enumeration.File)
	results := make(chan []reporting.Finding, o.Workers)
	var wg sync.WaitGroup
	var inspected atomic.Int64
	for i := 0; i < o.Workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for f := range jobs {
				if ctx.Err() != nil {
					continue
				}
				if f.Size < 0 || f.Size > o.MaxBytes || !o.Config.Extensions[enumeration.Extension(f.Path)] {
					continue
				}
				h, err := root.Open(f.Path)
				if err != nil {
					continue
				}
				b, err := io.ReadAll(io.LimitReader(h, o.MaxBytes+1))
				_ = h.Close()
				if err != nil || int64(len(b)) > o.MaxBytes {
					continue
				}
				inspected.Add(1)
				matches := o.Config.Detect(b)
				if len(matches) == 0 {
					continue
				}
				out := make([]reporting.Finding, 0, len(matches))
				for _, m := range matches {
					out = append(out, reporting.Finding{Target: o.Target, Share: o.Share, Path: strings.TrimPrefix(f.Path, "./"), Category: m.Category, Keyword: m.Keyword, Confidence: m.Confidence, Line: m.Line, Evidence: m.Evidence, Size: f.Size, Modified: f.ModTime})
				}
				results <- out
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, f := range files {
			select {
			case jobs <- f:
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	all := []reporting.Finding{}
	for r := range results {
		all = append(all, r...)
	}
	return all, int(inspected.Load())
}
