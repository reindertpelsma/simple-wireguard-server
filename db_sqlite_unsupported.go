//go:build linux && (mips || mipsle)

package main

import (
	"fmt"

	"gorm.io/gorm"
)

func sqliteDialector(path string) (gorm.Dialector, error) {
	return nil, fmt.Errorf("sqlite is not supported on this build target; use -db-type mysql or -db-type postgres")
}
