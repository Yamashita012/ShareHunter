package enumeration

import (
	"context"
	"io/fs"
	"path"
	"strings"
)

type File struct {
	Path    string
	Size    int64
	ModTime int64
}
type Options struct{ MaxDepth, MaxFiles int }

func Walk(ctx context.Context, root fs.FS, o Options) ([]File, int, []string) {
	if o.MaxFiles <= 0 {
		o.MaxFiles = 1000000
	}
	out := []File{}
	dirs := 0
	errs := []string{}
	var visit func(string, int)
	visit = func(dir string, depth int) {
		if ctx.Err() != nil || len(out) >= o.MaxFiles {
			return
		}
		entries, err := fs.ReadDir(root, dir)
		if err != nil {
			errs = append(errs, dir+": "+err.Error())
			return
		}
		if dir != "." {
			dirs++
		}
		for _, ent := range entries {
			if ctx.Err() != nil || len(out) >= o.MaxFiles {
				return
			}
			p := path.Join(dir, ent.Name())
			if ent.IsDir() {
				if depth < o.MaxDepth {
					visit(p, depth+1)
				}
				continue
			}
			info, e := ent.Info()
			if e != nil {
				errs = append(errs, p+": "+e.Error())
				continue
			}
			out = append(out, File{Path: p, Size: info.Size(), ModTime: info.ModTime().Unix()})
		}
	}
	visit(".", 0)
	return out, dirs, errs
}
func Extension(p string) string { x := strings.ToLower(path.Ext(p)); return strings.TrimPrefix(x, ".") }
