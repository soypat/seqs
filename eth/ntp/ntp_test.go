package ntp

import (
	"testing"
	"time"
)

func TestTimestamp(t *testing.T) {
	now := time.Now()
	nowp1 := now.Add(time.Second)
	t1, err := TimestampFromTime(now)
	if err != nil {
		t.Fatal(err)
	}
	t2, _ := TimestampFromTime(nowp1)
	gotnow := t1.Time()
	if gotnow.Sub(now) > time.Microsecond {
		t.Fatalf("got %v, want %v", gotnow, now)
	}

	d := t2.Sub(t1)
	if d != time.Second {
		t.Fatalf("expected 1s, got %s", d)
	}
	d = t1.Sub(t2)
	if d != -time.Second {
		t.Fatalf("expected -1s, got %s", d)
	}
}
