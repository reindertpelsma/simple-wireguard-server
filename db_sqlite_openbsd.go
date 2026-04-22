//go:build openbsd

package main

import (
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func sqliteDialector(path string) (gorm.Dialector, error) {
	return sqlite.Open(path), nil
}
