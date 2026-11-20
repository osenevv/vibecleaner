package payments

import "testing"

func TestRemainderAfterPartialIsAccepted(t *testing.T) {
	charge := &Charge{Captured: 1000, Refunded: 0}
	if _, err := Refund(charge, 400); err != nil {
		t.Fatal(err)
	}
	got, err := Refund(charge, 600)
	if err != nil {
		t.Fatal(err)
	}
	if got != 1000 || charge.Refunded != 1000 {
		t.Fatalf("refunded = %d", charge.Refunded)
	}
}

func TestPartialPastRemainderIsRefused(t *testing.T) {
	charge := &Charge{Captured: 1000, Refunded: 0}
	if _, err := Refund(charge, 700); err != nil {
		t.Fatal(err)
	}
	if _, err := Refund(charge, 400); err == nil {
		t.Fatal("expected error")
	}
	if charge.Refunded != 700 {
		t.Fatalf("refunded = %d", charge.Refunded)
	}
}

func TestSecondFullRefundIsRefused(t *testing.T) {
	charge := &Charge{Captured: 1000, Refunded: 0}
	if _, err := Refund(charge, 1000); err != nil {
		t.Fatal(err)
	}
	if _, err := Refund(charge, 1000); err == nil {
		t.Fatal("expected error")
	}
	if charge.Refunded != 1000 {
		t.Fatalf("refunded = %d", charge.Refunded)
	}
}
