package payments

import "errors"

type Charge struct {
	Captured int
	Refunded int
}

func Refund(charge *Charge, amount int) (int, error) {
	if amount < 1 || amount > charge.Captured {
		return charge.Refunded, errors.New("refund is outside the captured amount")
	}
	charge.Refunded += amount
	return charge.Refunded, nil
}
