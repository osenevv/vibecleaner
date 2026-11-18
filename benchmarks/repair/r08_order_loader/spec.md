# Customer orders

`load_customer_orders` returns that customer's orders, each with its lines. An unknown customer returns an empty list. Use `orders_for` and `lines_for`. A customer with any number of orders and lines costs two queries: one for the orders, and a second for the lines only when there is at least one order. Zero orders is one query and no line query.

Line order follows `line_ids`. Order order follows `orders_for`.
