"""Languages without a grammar still get token mutants on the changed lines."""

from vibeguard.probes.mutate import file_candidates


def test_go_comparison_and_integer_are_mutated() -> None:
    source = "func toll(n int) int {\n\tif n == 1 {\n\t\treturn 3\n\t}\n\treturn 0\n}\n"
    mutants = file_candidates("payments/refund.go", source, frozenset({2, 3}))
    operators = {mutant.operator for mutant in mutants}
    assert "cmp_flip" in operators
    assert "off_by_one" in operators
    assert any("n != 1" in mutant.source for mutant in mutants)
    assert any("return 4" in mutant.source for mutant in mutants)
    assert all("return 0" in mutant.source for mutant in mutants)


def test_unchanged_go_lines_stay_put() -> None:
    source = "func toll(n int) bool {\n\treturn n == 1\n}\n"
    assert file_candidates("refund.go", source, frozenset({1})) == []
