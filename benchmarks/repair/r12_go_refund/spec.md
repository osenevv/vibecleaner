# Charge refunds

`Refund` applies one refund to a captured charge. Amounts are integer cents. A refund below 1 cent, or a refund that would make the total refunded greater than the captured amount, returns an error and leaves the charge unchanged. A second refund is allowed only for whatever captured cents are still unrefunded.

Refunding the full captured amount, then refunding it again, returns an error. Refunding 400 then 600 of a 1000 cent charge succeeds and records 1000 refunded.
