package store

import (
	"encoding/json"
	"testing"
	"time"
)

type testObject struct {
	Name string `json:"name"`
	Timestamps
}

// withClock makes Now return each of times in turn, restoring it after t.
func withClock(t *testing.T, times ...time.Time) {
	t.Helper()
	orig := Now
	i := 0
	Now = func() time.Time {
		now := times[i]
		if i < len(times)-1 {
			i++
		}
		return now
	}
	t.Cleanup(func() { Now = orig })
}

func newTestStore(t *testing.T) Store {
	t.Helper()
	s, err := NewLocalStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewLocalStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestPutObjectStampsCreateAndUpdate(t *testing.T) {
	t1 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Hour)
	withClock(t, t1, t2)
	s := newTestStore(t)
	const key = "/kayra/obj/config"

	created := testObject{Name: "a"}
	if err := PutObject(s, key, &created); err != nil {
		t.Fatalf("PutObject create: %v", err)
	}
	if !created.CreatedAt.Equal(t1) || !created.UpdatedAt.Equal(t1) {
		t.Fatalf("create stamped %v/%v, want both %v", created.CreatedAt, created.UpdatedAt, t1)
	}

	// An update built from scratch (as a PUT handler does) carries no
	// timestamps of its own: CreatedAt must come from the stored record.
	updated := testObject{Name: "b"}
	if err := PutObject(s, key, &updated); err != nil {
		t.Fatalf("PutObject update: %v", err)
	}
	if !updated.CreatedAt.Equal(t1) {
		t.Fatalf("update CreatedAt = %v, want preserved %v", updated.CreatedAt, t1)
	}
	if !updated.UpdatedAt.Equal(t2) {
		t.Fatalf("update UpdatedAt = %v, want %v", updated.UpdatedAt, t2)
	}

	var stored testObject
	if err := GetJSON(s, key, &stored); err != nil {
		t.Fatalf("GetJSON: %v", err)
	}
	if stored != updated {
		t.Fatalf("stored %+v, want %+v", stored, updated)
	}
}

func TestPutObjectIgnoresClientTimestamps(t *testing.T) {
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	withClock(t, now)
	s := newTestStore(t)

	forged := time.Date(1999, 1, 1, 0, 0, 0, 0, time.UTC)
	obj := testObject{Name: "a", Timestamps: Timestamps{CreatedAt: forged, UpdatedAt: forged}}
	if err := PutObject(s, "/kayra/obj/config", &obj); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if !obj.CreatedAt.Equal(now) || !obj.UpdatedAt.Equal(now) {
		t.Fatalf("stamped %v/%v, want both %v", obj.CreatedAt, obj.UpdatedAt, now)
	}
}

func TestPutObjectBackfillsLegacyRecord(t *testing.T) {
	now := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	withClock(t, now)
	s := newTestStore(t)
	const key = "/kayra/obj/config"

	// A record written before timestamps existed.
	if err := s.Put(key, []byte(`{"name":"a"}`)); err != nil {
		t.Fatalf("Put: %v", err)
	}
	obj := testObject{Name: "a"}
	if err := PutObject(s, key, &obj); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if !obj.CreatedAt.Equal(now) || !obj.UpdatedAt.Equal(now) {
		t.Fatalf("stamped %v/%v, want both %v", obj.CreatedAt, obj.UpdatedAt, now)
	}
}

func TestTimestampsJSONIsFlattened(t *testing.T) {
	ts := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	data, err := json.Marshal(testObject{Name: "a", Timestamps: Timestamps{CreatedAt: ts, UpdatedAt: ts}})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := `{"name":"a","created_at":"2026-01-01T10:00:00Z","updated_at":"2026-01-01T10:00:00Z"}`
	if string(data) != want {
		t.Fatalf("Marshal = %s, want %s", data, want)
	}
}
