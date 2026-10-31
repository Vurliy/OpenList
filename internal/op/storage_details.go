package op

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/singleflight"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const (
	// detailsStateIdleTTL is how long an idle per-mount state is retained.
	detailsStateIdleTTL = int64(86400)
	// detailsStatePruneInterval throttles the O(n) prune of detailsStates.
	detailsStatePruneInterval = int64(3600)

	defaultStorageDetailsTimeoutSec = 15
	maxStorageDetailsTimeoutSec     = 600
	maxStorageDetailsCooldownSec    = int(detailsStateIdleTTL)
)

type storageDetailsState struct {
	// generation is drawn from the global detailsGenSeq, so it is unique for
	// the process lifetime. A state can therefore be pruned and recreated
	// without a late probe of the old state ever matching the new one.
	generation uint64
	lastDone   int64
	updated    int64
	refreshing bool
}

// A changing driver is identified by the object, since reinitialization may
// mutate its mount path. Failed or retired objects remain unavailable until a
// successful initialization; their capacity must not be published again.
type storageDetailsChange struct {
	paths  []string
	active bool
}

var (
	detailsG       singleflight.Group[*model.StorageDetails]
	detailsLock    sync.Mutex
	detailsStates  = make(map[string]*storageDetailsState)
	detailsChanges = make(map[driver.Driver]*storageDetailsChange)
	detailsGenSeq  uint64
	detailsPruned  int64
)

func nextStorageDetailsGenerationLocked() uint64 {
	detailsGenSeq++
	return detailsGenSeq
}

func storageDetailsStateLocked(key string) *storageDetailsState {
	state := detailsStates[key]
	if state == nil {
		state = &storageDetailsState{
			generation: nextStorageDetailsGenerationLocked(),
			updated:    time.Now().Unix(),
		}
		detailsStates[key] = state
	}
	return state
}

func invalidateStorageDetailsLocked(key string) {
	state := storageDetailsStateLocked(key)
	state.generation = nextStorageDetailsGenerationLocked()
	state.lastDone = 0
	state.refreshing = false
	state.updated = time.Now().Unix()
	Cache.detailCache.Delete(key)
}

// InvalidateStorageDetailsState drops cached capacity and supersedes any
// in-flight probe for mountPath.
func InvalidateStorageDetailsState(mountPath string) {
	detailsLock.Lock()
	defer detailsLock.Unlock()
	invalidateStorageDetailsLocked(utils.FixAndCleanPath(mountPath))
	maybePruneStorageDetailsStatesLocked(time.Now().Unix())
}

func maybePruneStorageDetailsStatesLocked(now int64) {
	if now-detailsPruned < detailsStatePruneInterval {
		return
	}
	detailsPruned = now
	pruneStorageDetailsStatesLocked(now)
}

// pruneStorageDetailsStatesLocked deletes states that have been idle for
// detailsStateIdleTTL. Active refreshes and mounts under an active change are
// kept. Deletion is safe because generations are globally unique.
func pruneStorageDetailsStatesLocked(now int64) {
	changing := make(map[string]struct{})
	for _, change := range detailsChanges {
		for _, key := range change.paths {
			changing[key] = struct{}{}
		}
	}
	for key, state := range detailsStates {
		if state.refreshing || now-state.updated <= detailsStateIdleTTL {
			continue
		}
		if _, ok := changing[key]; ok {
			continue
		}
		delete(detailsStates, key)
	}
}

// storageDetailsSettings reads and clamps the cooldown and timeout settings.
func storageDetailsSettings() (cooldownSec int, timeout time.Duration) {
	cooldownSec = GetSettingInt(conf.StorageDetailsCooldownSeconds, 0)
	if cooldownSec < 0 {
		cooldownSec = 0
	} else if cooldownSec > maxStorageDetailsCooldownSec {
		cooldownSec = maxStorageDetailsCooldownSec
	}
	timeoutSec := GetSettingInt(conf.StorageDetailsTimeoutSeconds, defaultStorageDetailsTimeoutSec)
	if timeoutSec <= 0 {
		timeoutSec = defaultStorageDetailsTimeoutSec
	} else if timeoutSec > maxStorageDetailsTimeoutSec {
		timeoutSec = maxStorageDetailsTimeoutSec
	}
	return cooldownSec, time.Duration(timeoutSec) * time.Second
}

func beginStorageDetailsChange(storage driver.Driver, paths ...string) (*storageDetailsChange, error) {
	detailsLock.Lock()
	defer detailsLock.Unlock()
	if previous := detailsChanges[storage]; previous != nil && previous.active {
		return nil, errors.WithMessage(errs.StorageNotInit, "storage is being reinitialized")
	}
	change := &storageDetailsChange{active: true}
	for _, path := range paths {
		key := utils.FixAndCleanPath(path)
		if utils.SliceContains(change.paths, key) {
			continue
		}
		change.paths = append(change.paths, key)
		invalidateStorageDetailsLocked(key)
	}
	detailsChanges[storage] = change
	return change, nil
}

func finishStorageDetailsChange(storage driver.Driver, change *storageDetailsChange, ready bool) {
	detailsLock.Lock()
	defer detailsLock.Unlock()
	if detailsChanges[storage] != change {
		return
	}
	for _, key := range change.paths {
		invalidateStorageDetailsLocked(key)
	}
	change.active = false
	if !ready {
		if meta := storage.GetStorage(); meta != nil && meta.Status == WORK {
			meta.SetStatus(DISABLED)
		}
	}
	delete(detailsChanges, storage)
}

type storageDetailsSnapshot struct {
	key        string
	generation uint64
	ttl        time.Duration
	cache      bool
}

// Admission and DoChan registration share one short critical section. No
// caller can reserve a generation and register its flight after a later one
// has already completed. The driver call itself never holds detailsLock.
func prepareStorageDetails(ctx context.Context, storage driver.Driver, refresh bool, cooldownSec int, timeout time.Duration) (<-chan singleflight.Result[*model.StorageDetails], *model.StorageDetails, error) {
	detailsLock.Lock()
	defer detailsLock.Unlock()
	if detailsChanges[storage] != nil {
		return nil, nil, errors.WithMessage(errs.StorageNotInit, "storage details unavailable during or after an unsuccessful storage change")
	}
	config := storage.Config()
	meta := storage.GetStorage()
	if meta == nil || meta.Status != WORK {
		status := ""
		if meta != nil {
			status = meta.Status
		}
		return nil, nil, errors.WithMessagef(errs.StorageNotInit, "storage status: %s", status)
	}
	wd, ok := storage.(driver.WithDetails)
	if !ok {
		return nil, nil, errs.NotImplement
	}
	snapshot := storageDetailsSnapshot{
		key:   utils.FixAndCleanPath(meta.MountPath),
		ttl:   time.Minute * time.Duration(meta.CacheExpiration),
		cache: !config.NoCache,
	}
	if registered, ok := storagesMap.Load(snapshot.key); ok && registered != storage {
		return nil, nil, errors.WithMessage(errs.StorageNotInit, "storage driver has been replaced")
	}
	state := storageDetailsStateLocked(snapshot.key)
	if refresh && !state.refreshing && (cooldownSec <= 0 || time.Now().Unix()-state.lastDone >= int64(cooldownSec)) {
		invalidateStorageDetailsLocked(snapshot.key)
		state.refreshing = true
	} else if cached, exists := Cache.detailCache.Get(snapshot.key); exists && snapshot.cache {
		return nil, cached, nil
	}
	snapshot.generation = state.generation
	flightKey := fmt.Sprintf("%s:%d", snapshot.key, snapshot.generation)
	result := detailsG.DoChan(flightKey, func() (*model.StorageDetails, error) {
		return probeStorageDetails(ctx, wd, snapshot, timeout)
	})
	return result, nil, nil
}

func probeStorageDetails(ctx context.Context, storage driver.WithDetails, snapshot storageDetailsSnapshot, timeout time.Duration) (ret *model.StorageDetails, err error) {
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	defer cancel()
	defer func() {
		if recovered := recover(); recovered != nil {
			ret = nil
			err = fmt.Errorf("panic in driver GetDetails: %v", recovered)
			log.Errorf("panic recovered in driver GetDetails for %s: %v", snapshot.key, recovered)
		}
		detailsLock.Lock()
		defer detailsLock.Unlock()
		state := storageDetailsStateLocked(snapshot.key)
		if state.generation != snapshot.generation {
			log.Debugf("discarding stale storage details for %s: generation %d was superseded by %d", snapshot.key, snapshot.generation, state.generation)
			return
		}
		now := time.Now().Unix()
		state.refreshing = false
		state.updated = now
		if err == nil {
			if snapshot.cache {
				Cache.detailCache.SetWithTTL(snapshot.key, ret, snapshot.ttl)
			}
			state.lastDone = now
		}
		maybePruneStorageDetailsStatesLocked(now)
	}()
	ret, err = callGetDetailsWithDeadline(probeCtx, storage, snapshot.key)
	if err != nil {
		ret = nil
	} else if probeCtx.Err() != nil {
		// Do not publish a nominal success that arrives after the probe deadline.
		ret, err = nil, probeCtx.Err()
	}
	return ret, err
}

type storageDetailsOutcome struct {
	val *model.StorageDetails
	err error
}

// callGetDetailsWithDeadline returns no later than ctx's deadline even if the
// driver ignores cancellation, so a hung driver cannot keep the flight (and
// the refresh barrier of its mount) open forever. A late result is dropped.
func callGetDetailsWithDeadline(ctx context.Context, storage driver.WithDetails, key string) (*model.StorageDetails, error) {
	done := make(chan storageDetailsOutcome, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				log.Errorf("panic recovered in driver GetDetails for %s: %v", key, recovered)
				done <- storageDetailsOutcome{err: fmt.Errorf("panic in driver GetDetails: %v", recovered)}
			}
		}()
		val, err := storage.GetDetails(ctx)
		done <- storageDetailsOutcome{val: val, err: err}
	}()
	select {
	case outcome := <-done:
		return outcome.val, outcome.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func GetStorageDetails(ctx context.Context, storage driver.Driver, refresh ...bool) (*model.StorageDetails, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cooldownSec, timeout := storageDetailsSettings()
	result, cached, err := prepareStorageDetails(ctx, storage, utils.IsBool(refresh...), cooldownSec, timeout)
	if err != nil || result == nil {
		return cached, err
	}
	select {
	case ret := <-result:
		return ret.Val, ret.Err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
