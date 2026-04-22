//go:build !(linux && (mips || mipsle))

package main

import (
	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

func sqliteDialector(path string) (gorm.Dialector, error) {
	return sqlite.Open(path), nil
}
