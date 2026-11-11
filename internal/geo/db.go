package geo

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

var (
	ErrUnavailable = errors.New("geo database unavailable")
	ErrStale       = errors.New("geo database stale")
)

// Record is the subset of a GeoLite2 country/city record used for policy.
type Record struct {
	Country            string
	RegisteredCountry  string
	RepresentedCountry string
	Subdivisions       []string
}

type dbRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	RepresentedCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"represented_country"`
	Subdivisions []struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"subdivisions"`
}

// Locator is the lookup surface used by the HTTP server.
type Locator interface {
	Locate(ip netip.Addr) (Record, error)
	Ready() bool
}

// Database is a hot-swappable MaxMind reader. Lookups fail closed when the
// file is missing, unreadable, or older than maxStale.
type Database struct {
	mu       sync.RWMutex
	reader   *maxminddb.Reader
	path     string
	edition  string
	maxStale time.Duration
	now      func() time.Time
}

func NewDatabase(path, edition string, maxStale time.Duration) *Database {
	return &Database{
		path:     path,
		edition:  edition,
		maxStale: maxStale,
		now:      time.Now,
	}
}

func (d *Database) Path() string { return d.path }

func (d *Database) SetNow(now func() time.Time) {
	if now != nil {
		d.now = now
	}
}

// Reload opens the database at path and swaps it in only after the file parses.
func (d *Database) Reload() error {
	reader, err := maxminddb.Open(d.path)
	if err != nil {
		return fmt.Errorf("%w: %s", ErrUnavailable, err.Error())
	}
	if reader.Metadata.DatabaseType != d.edition {
		reader.Close()
		return fmt.Errorf("%w: database type %q, want %q", ErrUnavailable, reader.Metadata.DatabaseType, d.edition)
	}
	if reader.Metadata.BuildEpoch == 0 {
		reader.Close()
		return fmt.Errorf("%w: missing build epoch", ErrUnavailable)
	}
	d.mu.Lock()
	old := d.reader
	d.reader = reader
	d.mu.Unlock()
	if old != nil {
		old.Close()
	}
	return nil
}

func (d *Database) Close() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.reader == nil {
		return nil
	}
	err := d.reader.Close()
	d.reader = nil
	return err
}

func (d *Database) Ready() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.freshLocked()
}

func (d *Database) Locate(ip netip.Addr) (Record, error) {
	if !ip.IsValid() {
		return Record{}, fmt.Errorf("%w: invalid ip", ErrUnavailable)
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.reader == nil {
		return Record{}, ErrUnavailable
	}
	if !d.freshLocked() {
		return Record{}, ErrStale
	}
	var raw dbRecord
	if err := d.reader.Lookup(net.IP(ip.Unmap().AsSlice()), &raw); err != nil {
		return Record{}, fmt.Errorf("%w: %s", ErrUnavailable, err.Error())
	}
	rec := Record{
		Country:            raw.Country.ISOCode,
		RegisteredCountry:  raw.RegisteredCountry.ISOCode,
		RepresentedCountry: raw.RepresentedCountry.ISOCode,
	}
	for _, sub := range raw.Subdivisions {
		if sub.ISOCode != "" {
			rec.Subdivisions = append(rec.Subdivisions, sub.ISOCode)
		}
	}
	return rec, nil
}

func (d *Database) freshLocked() bool {
	if d.reader == nil || d.reader.Metadata.BuildEpoch == 0 {
		return false
	}
	built := time.Unix(int64(d.reader.Metadata.BuildEpoch), 0)
	return d.now().Sub(built) <= d.maxStale
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
