package webdavauth

import (
	"fmt"
	"sync"
)

var (
	epochMu         sync.RWMutex
	userFileEpoch   = make(map[string]int)
	globalFileEpoch = make(map[string]int)
)

func GetGlobalFileEpoch(canonicalPath string) int {
	epochMu.RLock()
	defer epochMu.RUnlock()
	if v, ok := globalFileEpoch[canonicalPath]; ok && v > 0 {
		return v
	}
	return 1
}

func SetGlobalFileEpoch(canonicalPath string, epoch int) {
	epochMu.Lock()
	defer epochMu.Unlock()
	globalFileEpoch[canonicalPath] = epoch
}

func IncrementGlobalFileEpoch(canonicalPath string) int {
	epochMu.Lock()
	defer epochMu.Unlock()
	cur := globalFileEpoch[canonicalPath]
	if cur <= 0 {
		cur = 1
	}
	cur++
	globalFileEpoch[canonicalPath] = cur
	return cur
}

func GetUserFileEpoch(uid uint, canonicalPath string) int {
	epochMu.RLock()
	defer epochMu.RUnlock()
	key := fmt.Sprintf("%d:%s", uid, canonicalPath)
	if v, ok := userFileEpoch[key]; ok && v > 0 {
		return v
	}
	return 1
}

func SetUserFileEpoch(uid uint, canonicalPath string, epoch int) {
	epochMu.Lock()
	defer epochMu.Unlock()
	key := fmt.Sprintf("%d:%s", uid, canonicalPath)
	userFileEpoch[key] = epoch
}

func IncrementUserFileEpoch(uid uint, canonicalPath string) int {
	epochMu.Lock()
	defer epochMu.Unlock()
	key := fmt.Sprintf("%d:%s", uid, canonicalPath)
	cur := userFileEpoch[key]
	if cur <= 0 {
		cur = 1
	}
	cur++
	userFileEpoch[key] = cur
	return cur
}
