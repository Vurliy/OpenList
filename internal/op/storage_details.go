package op

import (
	"context"
	"fmt"
	"strconv"
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
	defaultDetailsTimeoutSec = 15
	maxDetailsTimeoutSec     = 600
	maxDetailsCooldownSec    = 86400
)

// detailsState belongs to one mount path. Its generation is drawn from a
// process-wide sequence, and the state is deleted whenever the mount changes,
// so a probe started before a change can never publish into the cache after
// it: its generation no longer matches (or its state no longer exists).
type detailsState struct {
	generation uint64
	lastDone   int64 // unix time of the last successful probe, for cooldown
}

var (
	detailsG        singleflight.Group[*model.StorageDetails]
	detailsLock     sync.Mutex
	detailsStates   = make(map[string]*detailsState)
	detailsChanging = make(map[string]int) // mount path -> active lifecycle changes
	detailsSeq      uint64
)

func invalidateStorageDetailsLocked(key string) {
	delete(detailsStates, key)
	Cache.detailCache.Delete(key)
}

// beginStorageDetailsChange marks mount paths as changing (init, update,
// disable, delete) and drops their cached capacity. While a path is changing
// no probe is admitted for it. Call the returned function when the change is
// done; it drops anything cached in between. Changes may nest.
func beginStorageDetailsChange(mountPaths ...string) (end func()) {
	keys := make([]string, 0, len(mountPaths))
	for _, p := range mountPaths {
		if key := utils.FixAndCleanPath(p); !utils.SliceContains(keys, key) {
			keys = append(keys, key)
		}
	}
	detailsLock.Lock()
	for _, key := range keys {
		detailsChanging[key]++
		invalidateStorageDetailsLocked(key)
	}
	detailsLock.Unlock()
	return func() {
		detailsLock.Lock()
		defer detailsLock.Unlock()
		for _, key := range keys {
			if detailsChanging[key]--; detailsChanging[key] <= 0 {
				delete(detailsChanging, key)
			}
			invalidateStorageDetailsLocked(key)
		}
	}
}

// storageDetailsSettings reads the cooldown and timeout settings and clamps
// them to sane ranges, so a bad value cannot disable every probe.
func storageDetailsSettings() (cooldownSec int64, timeout time.Duration) {
	cooldown := getSettingInt(conf.StorageDetailsCooldownSeconds, 0)
	cooldown = min(max(cooldown, 0), maxDetailsCooldownSec)
	timeoutSec := getSettingInt(conf.StorageDetailsTimeoutSeconds, defaultDetailsTimeoutSec)
	if timeoutSec <= 0 {
		timeoutSec = defaultDetailsTimeoutSec
	}
	timeoutSec = min(timeoutSec, maxDetailsTimeoutSec)
	return int64(cooldown), time.Duration(timeoutSec) * time.Second
}

func getSettingInt(key string, defaultValue int) int {
	if item, err := GetSettingItemByKey(key); err == nil && item != nil {
		if val, err := strconv.Atoi(item.Value); err == nil {
			return val
		}
	}
	return defaultValue
}

type detailsProbe struct {
	key        string
	generation uint64
	cache      bool
	ttl        time.Duration
	timeout    time.Duration
}

// prepareStorageDetails returns either a cached value or a channel for a
// (possibly shared) probe. Admission and flight registration happen under one
// lock, so a probe can never be registered for a generation that a lifecycle
// change has already retired.
func prepareStorageDetails(ctx context.Context, storage driver.Driver, refresh bool, cooldownSec int64, timeout time.Duration) (<-chan singleflight.Result[*model.StorageDetails], *model.StorageDetails, error) {
	meta := storage.GetStorage()
	if storage.Config().CheckStatus && meta.Status != WORK {
		return nil, nil, errors.WithMessagef(errs.StorageNotInit, "storage status: %s", meta.Status)
	}
	wd, ok := storage.(driver.WithDetails)
	if !ok {
		return nil, nil, errs.NotImplement
	}
	probe := detailsProbe{
		key:     utils.FixAndCleanPath(meta.MountPath),
		cache:   !storage.Config().NoCache,
		ttl:     time.Minute * time.Duration(meta.CacheExpiration),
		timeout: timeout,
	}

	detailsLock.Lock()
	defer detailsLock.Unlock()
	if detailsChanging[probe.key] > 0 {
		return nil, nil, errors.WithMessage(errs.StorageNotInit, "storage is being changed")
	}
	// A driver that was disabled, deleted or replaced may still be held by a
	// caller; it must not report (or cache) capacity for the mount path.
	if registered, ok := storagesMap.Load(probe.key); !ok || registered != storage {
		return nil, nil, errors.WithMessage(errs.StorageNotInit, "storage is not mounted")
	}
	state := detailsStates[probe.key]
	if state == nil {
		detailsSeq++
		state = &detailsState{generation: detailsSeq}
		detailsStates[probe.key] = state
	}
	// A refresh bypasses the cache unless it falls inside the cooldown, in
	// which case it is served like a normal request.
	bypassCache := refresh && (cooldownSec <= 0 || time.Now().Unix()-state.lastDone >= cooldownSec)
	if !bypassCache && probe.cache {
		if cached, ok := Cache.detailCache.Get(probe.key); ok {
			return nil, cached, nil
		}
	}
	// A refresh joins a probe that is already running: it started after the
	// refresh was requested, or at most one timeout earlier.
	probe.generation = state.generation
	flightKey := fmt.Sprintf("%s#%d", probe.key, probe.generation)
	return detailsG.DoChan(flightKey, func() (*model.StorageDetails, error) {
		return runStorageDetailsProbe(ctx, wd, probe)
	}), nil, nil
}

// runStorageDetailsProbe is detached from the caller's cancellation, because
// its result is shared, and is bounded by its own timeout instead.
func runStorageDetailsProbe(ctx context.Context, wd driver.WithDetails, probe detailsProbe) (*model.StorageDetails, error) {
	probeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), probe.timeout)
	defer cancel()
	ret, err := getDetailsWithDeadline(probeCtx, wd, probe.key)
	if err != nil {
		return nil, err
	}
	detailsLock.Lock()
	defer detailsLock.Unlock()
	if state := detailsStates[probe.key]; state != nil && state.generation == probe.generation {
		state.lastDone = time.Now().Unix()
		if probe.cache {
			Cache.detailCache.SetWithTTL(probe.key, ret, probe.ttl)
		}
	}
	return ret, nil
}

type detailsOutcome struct {
	val *model.StorageDetails
	err error
}

// getDetailsWithDeadline returns by ctx's deadline even if the driver ignores
// cancellation, so a hung driver cannot hold the shared flight open forever.
// It also turns a driver panic into an error.
func getDetailsWithDeadline(ctx context.Context, wd driver.WithDetails, key string) (*model.StorageDetails, error) {
	done := make(chan detailsOutcome, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Errorf("panic in GetDetails of %s: %v", key, r)
				done <- detailsOutcome{err: fmt.Errorf("panic in GetDetails: %v", r)}
			}
		}()
		val, err := wd.GetDetails(ctx)
		done <- detailsOutcome{val: val, err: err}
	}()
	select {
	case out := <-done:
		return out.val, out.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func GetStorageDetails(ctx context.Context, storage driver.Driver, refresh ...bool) (*model.StorageDetails, error) {
	cooldownSec, timeout := storageDetailsSettings()
	result, cached, err := prepareStorageDetails(ctx, storage, utils.IsBool(refresh...), cooldownSec, timeout)
	if err != nil || result == nil {
		return cached, err
	}
	select {
	case r := <-result:
		return r.Val, r.Err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
