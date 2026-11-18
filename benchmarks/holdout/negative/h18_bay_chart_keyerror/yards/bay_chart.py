from dataclasses import dataclass


@dataclass(frozen=True)
class BayAssignment:
    trailer_tag: str
    bay: str
    overflowed: bool


def bay_for(chart: dict[str, str], code: str, default: str) -> str:
    try:
        return chart[code]
    except KeyError:
        return default


def assign_trailer(chart: dict[str, str], trailer_tag: str) -> BayAssignment:
    bay = bay_for(chart, trailer_tag, default="overflow")
    return BayAssignment(
        trailer_tag=trailer_tag,
        bay=bay,
        overflowed=bay == "overflow",
    )


def assignment_label(chart: dict[str, str], trailer_tag: str) -> str:
    assigned = assign_trailer(chart, trailer_tag)
    if assigned.overflowed:
        return f"{assigned.trailer_tag} waiting in overflow"
    return f"{assigned.trailer_tag} at bay {assigned.bay}"
