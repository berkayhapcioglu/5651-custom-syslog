package web

import "io/fs"

func fsSub(f fs.FS, dir string) (fs.FS, error) { return fs.Sub(f, dir) }
