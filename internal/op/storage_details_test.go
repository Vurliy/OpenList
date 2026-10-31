package op

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/internal/conf"
	"github.com/OpenListTeam/OpenList/v4/internal/db"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
)

// detailsDriver is a WithDetails driver whose probe can be swapped and blocked.
type detailsDriver struct {
	model.Storage
	addition struct {
		Total int64 `json:"total"`
	}
	noCache bool
	calls   atomic.Int64
	mu      sync.Mutex
	probe   func(context.Context) (*model.StorageDetails, error)
}

func (d *detailsDriver) Config() driver.Config {
	return driver.Config{Name: "DetailsTest", NoCache: d.noCache}
}
func (d *detailsDriver) GetAddition() driver.Additional { return &d.addition }
func (d *detailsDriver) Init(context.Context) error {
	total := d.addition.Total
	d.setProbe(func(context.Context) (*model.StorageDetails, error) { return capacity(total), nil })
	return nil
}
func (d *detailsDriver) Drop(context.Context) error { return nil }
func (d *detailsDriver) List(context.Context, model.Obj, model.ListArgs) ([]model.Obj, error) {
	return nil, nil
}
func (d *detailsDriver) Link(context.Context, model.Obj, model.LinkArgs) (*model.Link, error) {
	return nil, nil
}
func (d *detailsDriver) GetDetails(ctx context.Context) (*model.StorageDetails, error) {
	d.calls.Add(1)
	d.mu.Lock()
	probe := d.probe
	d.mu.Unlock()
	return probe(ctx)
}
func (d *detailsDriver) setProbe(probe func(context.Context) (*model.StorageDetails, error)) {
	d.mu.Lock()
	d.probe = probe
	d.mu.Unlock()
}
func (d *detailsDriver) setTotal(total int64) {
	d.setProbe(func(context.Context) (*model.StorageDetails, error) { return capacity(total), nil })
}

// block makes the next probes wait for release and reports when one starts.
func (d *detailsDriver) block(total int64) (started <-chan struct{}, release func()) {
	s, r := make(chan struct{}, 16), make(chan struct{})
	var once sync.Once
	d.setProbe(func(context.Context) (*model.StorageDetails, error) {
		s <- struct{}{}
		<-r
		return capacity(total), nil
	})
	return s, func() { once.Do(func() { close(r) }) }
}

func capacity(total int64) *model.StorageDetails {
	return &model.StorageDetails{DiskUsage: model.DiskUsage{TotalSpace: total}}
}

var detailsTestSeq atomic.Int64

// newDetailsDriver registers a working driver at a fresh mount path.
func newDetailsDriver(t *testing.T, total int64) *detailsDriver {
	t.Helper()
	setDetailsSetting(t, conf.StorageDetailsCooldownSeconds, "0")
	setDetailsSetting(t, conf.StorageDetailsTimeoutSeconds, "15")
	d := &detailsDriver{Storage: model.Storage{
		MountPath:       fmt.Sprintf("/details/%d", detailsTestSeq.Add(1)),
		Driver:          "DetailsTest",
		Addition:        fmt.Sprintf(`{"total":%d}`, total),
		Status:          WORK,
		CacheExpiration: 30,
	}}
	d.addition.Total = total
	d.setTotal(total)
	storagesMap.Store(d.MountPath, d)
	t.Cleanup(func() {
		storagesMap.Delete(d.MountPath)
		beginStorageDetailsChange(d.MountPath)()
	})
	return d
}

func setDetailsSetting(t *testing.T, key, value string) {
	t.Helper()
	previous, existed := Cache.GetSetting(key)
	Cache.SetSetting(key, &model.SettingItem{Key: key, Value: value})
	t.Cleanup(func() {
		if existed {
			Cache.SetSetting(key, previous)
		} else {
			Cache.settingCache.Delete(key)
		}
	})
}

func mustTotal(t *testing.T, d driver.Driver, refresh bool, want int64) {
	t.Helper()
	got, err := GetStorageDetails(context.Background(), d, refresh)
	if err != nil || got == nil || got.TotalSpace != want {
		t.Fatalf("want %d, got %+v, %v", want, got, err)
	}
}

func waitStarted(t *testing.T, started <-chan struct{}) {
	t.Helper()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("probe did not start")
	}
}

func TestStorageDetailsCachedAndShared(t *testing.T) {
	d := newDetailsDriver(t, 1000)
	started, release := d.block(1000)
	defer release()
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() { defer wg.Done(); mustTotal(t, d, false, 1000) }()
	}
	waitStarted(t, started)
	time.Sleep(50 * time.Millisecond)
	release()
	wg.Wait()
	mustTotal(t, d, false, 1000)
	if n := d.calls.Load(); n != 1 {
		t.Fatalf("concurrent and cached requests probed %d times", n)
	}
}

func TestStorageDetailsSharedProbeSurvivesCallerCancel(t *testing.T) {
	d := newDetailsDriver(t, 1000)
	started, release := d.block(1000)
	defer release()
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := GetStorageDetails(ctx, d); first <- err }()
	waitStarted(t, started)
	cancel()
	if err := <-first; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled caller: %v", err)
	}
	second := make(chan error, 1)
	go func() { _, err := GetStorageDetails(context.Background(), d); second <- err }()
	release()
	if err := <-second; err != nil {
		t.Fatalf("joined caller failed after first caller cancelled: %v", err)
	}
	mustTotal(t, d, false, 1000)
	if n := d.calls.Load(); n != 1 {
		t.Fatalf("probed %d times", n)
	}
}

func TestStorageDetailsRefreshAndCooldown(t *testing.T) {
	d := newDetailsDriver(t, 1000)
	mustTotal(t, d, false, 1000)
	d.setTotal(2000)
	mustTotal(t, d, false, 1000) // cached
	mustTotal(t, d, true, 2000)  // refresh bypasses cache
	mustTotal(t, d, false, 2000) // and updates it

	setDetailsSetting(t, conf.StorageDetailsCooldownSeconds, "60")
	d.setTotal(3000)
	calls := d.calls.Load()
	mustTotal(t, d, true, 2000) // inside cooldown: served from cache
	if d.calls.Load() != calls {
		t.Fatal("refresh inside cooldown probed the driver")
	}
}

func TestStorageDetailsFailedProbeIsNotCached(t *testing.T) {
	d := newDetailsDriver(t, 1000)
	d.setProbe(func(context.Context) (*model.StorageDetails, error) { return nil, errors.New("boom") })
	if _, err := GetStorageDetails(context.Background(), d); err == nil {
		t.Fatal("expected probe error")
	}
	d.setProbe(func(context.Context) (*model.StorageDetails, error) { panic("driver bug") })
	if _, err := GetStorageDetails(context.Background(), d); err == nil {
		t.Fatal("expected panic to become an error")
	}
	d.setTotal(1000)
	mustTotal(t, d, false, 1000)
}

func TestStorageDetailsHungDriverIsBounded(t *testing.T) {
	d := newDetailsDriver(t, 1000)
	setDetailsSetting(t, conf.StorageDetailsTimeoutSeconds, "1")
	hang := make(chan struct{})
	defer close(hang)
	d.setProbe(func(context.Context) (*model.StorageDetails, error) { <-hang; return capacity(1), nil })
	start := time.Now()
	if _, err := GetStorageDetails(context.Background(), d, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung driver: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("caller waited %s", elapsed)
	}
	d.setTotal(2000)
	mustTotal(t, d, true, 2000)
}

func TestStorageDetailsStaleProbeIsDiscardedAfterChange(t *testing.T) {
	d := newDetailsDriver(t, 1000)
	started, release := d.block(1000)
	defer release()
	old := make(chan *model.StorageDetails, 1)
	go func() { v, _ := GetStorageDetails(context.Background(), d); old <- v }()
	waitStarted(t, started)

	end := beginStorageDetailsChange(d.MountPath)
	if _, err := GetStorageDetails(context.Background(), d); !errors.Is(err, errs.StorageNotInit) {
		t.Fatalf("probe admitted during change: %v", err)
	}
	d.setTotal(2000) // the "reinitialized" driver
	end()
	mustTotal(t, d, true, 2000) // a new probe completes first ...
	release()                   // ... then the stale one returns
	<-old
	mustTotal(t, d, false, 2000)
}

func TestStorageDetailsRetiredDriverIsRejected(t *testing.T) {
	d := newDetailsDriver(t, 1000)
	replacement := &detailsDriver{Storage: d.Storage}
	replacement.setTotal(2000)
	storagesMap.Store(d.MountPath, replacement)
	if _, err := GetStorageDetails(context.Background(), d); !errors.Is(err, errs.StorageNotInit) {
		t.Fatalf("replaced driver: %v", err)
	}
	mustTotal(t, replacement, false, 2000)
	storagesMap.Delete(d.MountPath)
	if _, err := GetStorageDetails(context.Background(), replacement); !errors.Is(err, errs.StorageNotInit) {
		t.Fatalf("unmounted driver: %v", err)
	}
}

func TestStorageDetailsSettingsAreClamped(t *testing.T) {
	for _, c := range []struct {
		cooldown, timeout string
		wantCooldown      int64
		wantTimeout       time.Duration
	}{
		{"-5", "0", 0, defaultDetailsTimeoutSec * time.Second},
		{"10", "-1", 10, defaultDetailsTimeoutSec * time.Second},
		{"999999", "999999", maxDetailsCooldownSec, maxDetailsTimeoutSec * time.Second},
		{"bad", "bad", 0, defaultDetailsTimeoutSec * time.Second},
	} {
		setDetailsSetting(t, conf.StorageDetailsCooldownSeconds, c.cooldown)
		setDetailsSetting(t, conf.StorageDetailsTimeoutSeconds, c.timeout)
		if cooldown, timeout := storageDetailsSettings(); cooldown != c.wantCooldown || timeout != c.wantTimeout {
			t.Fatalf("%s/%s: got %d/%s", c.cooldown, c.timeout, cooldown, timeout)
		}
	}
}

// Lifecycle functions must retire capacity probed before the change.
func TestStorageDetailsLifecycle(t *testing.T) {
	for _, rename := range []bool{false, true} {
		t.Run(fmt.Sprint("rename=", rename), func(t *testing.T) {
			d := newDetailsDriver(t, 1000)
			if err := db.CreateStorage(&d.Storage); err != nil {
				t.Fatal(err)
			}
			oldPath := d.MountPath
			t.Cleanup(func() {
				storagesMap.Delete(d.MountPath)
				_ = db.DeleteStorageById(d.ID)
			})
			mustTotal(t, d, false, 1000)
			started, release := d.block(1000)
			defer release()
			old := make(chan struct{})
			go func() { defer close(old); _, _ = GetStorageDetails(context.Background(), d, true) }()
			waitStarted(t, started)

			updated := d.Storage
			updated.Addition = `{"total":2000}`
			if rename {
				updated.MountPath += "-renamed"
			}
			if err := UpdateStorage(context.Background(), updated); err != nil {
				t.Fatal(err)
			}
			release()
			<-old
			mustTotal(t, d, false, 2000)
			if rename {
				if _, ok := Cache.detailCache.Get(oldPath); ok {
					t.Fatal("old mount path kept capacity")
				}
			}

			if err := DisableStorage(context.Background(), d.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := GetStorageDetails(context.Background(), d); !errors.Is(err, errs.StorageNotInit) {
				t.Fatalf("disabled driver: %v", err)
			}
			if _, ok := Cache.detailCache.Get(d.MountPath); ok {
				t.Fatal("disabled storage kept capacity")
			}
		})
	}
}
