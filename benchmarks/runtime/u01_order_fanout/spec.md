# Order list

`GET /orders?account=ada` returns that account's orders and their lines. The response is 200 with `account` and `orders`. Each order has `id`, `title`, and `lines` of `sku` and `qty`. A missing account is 400. Any other path is 404.

Reading the list uses a constant number of queries, not one query per order.
