from dataclasses import dataclass


@dataclass(frozen=True)
class DockLoad:
    trailer_tag: str
    weight_kg: int
    priority: int
    chilled: bool


def rank_loads(loads: list[DockLoad]) -> list[DockLoad]:
    scored: list[tuple[int, DockLoad]] = []
    for load in loads:
        score = load.priority * 100 - (load.weight_kg // 10)
        if load.chilled:
            score += 40
        scored.append((score, load))
    scored.sort(key=lambda item: item[0], reverse=True)
    ordered: list[DockLoad] = []
    for _, load in scored:
        ordered.append(load)
    return ordered


def tags_in_order(loads: list[DockLoad]) -> list[str]:
    names: list[str] = []
    for load in rank_loads(loads):
        names.append(load.trailer_tag)
    return names


def first_chilled(loads: list[DockLoad]) -> DockLoad | None:
    for load in rank_loads(loads):
        if load.chilled:
            return load
    return None
