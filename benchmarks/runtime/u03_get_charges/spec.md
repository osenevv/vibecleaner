# Cart read

`GET /cart?account=ada` returns 200 and the account's cart total in cents. It does not write a charge. A missing account is 400. Any other path is 404.
