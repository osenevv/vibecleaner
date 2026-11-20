package payments

import "testing"

func TestValidInputFirstPartial(t *testing.T) {
	charge := &Charge{Captured: 1000, Refunded: 0}
	got, err := Refund(charge, 400)
	if err != nil {
		t.Fatal(err)
	}
	if got != 400 {
		t.Fatalf("got %d", got)
	}
}

func TestZeroIsRefused(t *testing.T) {
	charge := &Charge{Captured: 1000, Refunded: 0}
	if _, err := Refund(charge, 0); err == nil {
		t.Fatal("expected error")
	}
}

func TestAboveCapturedIsRefused(t *testing.T) {
	charge := &Charge{Captured: 1000, Refunded: 0}
	if _, err := Refund(charge, 1001); err == nil {
		t.Fatal("expected error")
	}
	if charge.Refunded != 0 {
		t.Fatalf("refunded = %d", charge.Refunded)
	}
}
