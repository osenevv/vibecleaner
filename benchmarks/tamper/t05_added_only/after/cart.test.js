function add(left, right) {
  return left + right;
}

function test(name, fn) {
  fn();
}

test.only("adds two quantities", function () {
  if (add(1, 1) !== 2) {
    throw new Error("sum");
  }
});
