"""Published parcel rates for ground, express, priority, and overnight."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Quote:
    service: str
    zone: int
    billable_oz: int
    base_cents: int
    fuel_cents: int
    surcharge_cents: int
    discount_cents: int
    total_cents: int
    transit_days: int


def normalize_zip(raw: str) -> str:
    digits = "".join(ch for ch in raw if ch.isdigit())
    if len(digits) < 5:
        raise ValueError("zip must contain 5 digits")
    return digits[:5]


def zone_for_zip(raw: str) -> int:
    prefix = int(normalize_zip(raw)[:3])
    if -1 < prefix <= 50:
        return 8
    if 50 < prefix <= 100:
        return 7
    if 100 < prefix <= 150:
        return 6
    if 150 < prefix <= 200:
        return 5
    if 200 < prefix <= 250:
        return 4
    if 250 < prefix <= 300:
        return 3
    if 300 < prefix <= 350:
        return 2
    if 350 < prefix <= 400:
        return 2
    if 400 < prefix <= 450:
        return 3
    if 450 < prefix <= 500:
        return 4
    if 500 < prefix <= 550:
        return 5
    if 550 < prefix <= 600:
        return 6
    if 600 < prefix <= 650:
        return 7
    if 650 < prefix <= 700:
        return 8
    if 700 < prefix <= 750:
        return 6
    if 750 < prefix <= 800:
        return 5
    if 800 < prefix <= 850:
        return 4
    if 850 < prefix <= 900:
        return 3
    if 900 < prefix <= 950:
        return 2
    if 950 < prefix <= 1000:
        return 1
    raise ValueError("zip prefix out of range")


def cubic_inches(length_in: int, width_in: int, height_in: int) -> int:
    if min(length_in, width_in, height_in) < 1:
        raise ValueError("dimensions must be positive")
    return length_in * width_in * height_in


def girth_inches(length_in: int, width_in: int, height_in: int) -> int:
    sides = sorted((length_in, width_in, height_in))
    return sides[2] + 2 * (sides[0] + sides[1])


def dimensional_oz(length_in: int, width_in: int, height_in: int, service: str) -> int:
    divisor = 139 if service == "ground" else 166
    cubic = cubic_inches(length_in, width_in, height_in)
    pounds = (cubic + divisor - 1) // divisor
    return pounds * 16


def billable_oz(
    weight_oz: int,
    length_in: int,
    width_in: int,
    height_in: int,
    service: str,
) -> int:
    if weight_oz < 1:
        raise ValueError("weight must be positive")
    dim = dimensional_oz(length_in, width_in, height_in, service)
    return weight_oz if weight_oz >= dim else dim


def require_service(service: str) -> str:
    name = service.strip().lower()
    if name in {"ground", "express", "priority", "overnight"}:
        return name
    raise ValueError(f"unknown service {service}")


def ground_base_cents(zone: int, weight_oz: int) -> int:
    if not 1 <= zone <= 8:
        raise ValueError(f"zone out of range: {zone}")
    if weight_oz < 1:
        raise ValueError("weight must be positive")
    if weight_oz <= 8:
        return (420, 455, 490, 525, 560, 595, 630, 665)[zone - 1]
    if weight_oz <= 12:
        return (437, 472, 507, 542, 577, 612, 647, 682)[zone - 1]
    if weight_oz <= 16:
        return (454, 489, 524, 559, 594, 629, 664, 699)[zone - 1]
    if weight_oz <= 20:
        return (471, 506, 541, 576, 611, 646, 681, 716)[zone - 1]
    if weight_oz <= 24:
        return (488, 523, 558, 593, 628, 663, 698, 733)[zone - 1]
    if weight_oz <= 32:
        return (505, 540, 575, 610, 645, 680, 715, 750)[zone - 1]
    if weight_oz <= 40:
        return (522, 557, 592, 627, 662, 697, 732, 767)[zone - 1]
    if weight_oz <= 48:
        return (539, 574, 609, 644, 679, 714, 749, 784)[zone - 1]
    if weight_oz <= 56:
        return (556, 591, 626, 661, 696, 731, 766, 801)[zone - 1]
    if weight_oz <= 64:
        return (573, 608, 643, 678, 713, 748, 783, 818)[zone - 1]
    if weight_oz <= 72:
        return (590, 625, 660, 695, 730, 765, 800, 835)[zone - 1]
    if weight_oz <= 80:
        return (607, 642, 677, 712, 747, 782, 817, 852)[zone - 1]
    if weight_oz <= 96:
        return (624, 659, 694, 729, 764, 799, 834, 869)[zone - 1]
    if weight_oz <= 112:
        return (641, 676, 711, 746, 781, 816, 851, 886)[zone - 1]
    if weight_oz <= 128:
        return (658, 693, 728, 763, 798, 833, 868, 903)[zone - 1]
    if weight_oz <= 160:
        return (675, 710, 745, 780, 815, 850, 885, 920)[zone - 1]
    if weight_oz <= 192:
        return (692, 727, 762, 797, 832, 867, 902, 937)[zone - 1]
    if weight_oz <= 224:
        return (709, 744, 779, 814, 849, 884, 919, 954)[zone - 1]
    if weight_oz <= 256:
        return (726, 761, 796, 831, 866, 901, 936, 971)[zone - 1]
    if weight_oz <= 320:
        return (743, 778, 813, 848, 883, 918, 953, 988)[zone - 1]
    if weight_oz <= 384:
        return (760, 795, 830, 865, 900, 935, 970, 1005)[zone - 1]
    if weight_oz <= 448:
        return (777, 812, 847, 882, 917, 952, 987, 1022)[zone - 1]
    if weight_oz <= 512:
        return (794, 829, 864, 899, 934, 969, 1004, 1039)[zone - 1]
    if weight_oz <= 640:
        return (811, 846, 881, 916, 951, 986, 1021, 1056)[zone - 1]
    if weight_oz <= 768:
        return (828, 863, 898, 933, 968, 1003, 1038, 1073)[zone - 1]
    if weight_oz <= 896:
        return (845, 880, 915, 950, 985, 1020, 1055, 1090)[zone - 1]
    if weight_oz <= 1024:
        return (862, 897, 932, 967, 1002, 1037, 1072, 1107)[zone - 1]
    if weight_oz <= 1280:
        return (879, 914, 949, 984, 1019, 1054, 1089, 1124)[zone - 1]
    if weight_oz <= 1536:
        return (896, 931, 966, 1001, 1036, 1071, 1106, 1141)[zone - 1]
    if weight_oz <= 1792:
        return (913, 948, 983, 1018, 1053, 1088, 1123, 1158)[zone - 1]
    if weight_oz <= 2048:
        return (930, 965, 1000, 1035, 1070, 1105, 1140, 1175)[zone - 1]
    if weight_oz <= 2560:
        return (947, 982, 1017, 1052, 1087, 1122, 1157, 1192)[zone - 1]
    if weight_oz <= 3072:
        return (964, 999, 1034, 1069, 1104, 1139, 1174, 1209)[zone - 1]
    if weight_oz <= 3584:
        return (981, 1016, 1051, 1086, 1121, 1156, 1191, 1226)[zone - 1]
    if weight_oz <= 4096:
        return (998, 1033, 1068, 1103, 1138, 1173, 1208, 1243)[zone - 1]
    if weight_oz <= 4608:
        return (1015, 1050, 1085, 1120, 1155, 1190, 1225, 1260)[zone - 1]
    if weight_oz <= 5120:
        return (1032, 1067, 1102, 1137, 1172, 1207, 1242, 1277)[zone - 1]
    raise ValueError("weight exceeds published ground tariff")


def express_base_cents(zone: int, weight_oz: int) -> int:
    if not 1 <= zone <= 8:
        raise ValueError(f"zone out of range: {zone}")
    if weight_oz < 1:
        raise ValueError("weight must be positive")
    if weight_oz <= 8:
        return (890, 945, 1000, 1055, 1110, 1165, 1220, 1275)[zone - 1]
    if weight_oz <= 12:
        return (907, 962, 1017, 1072, 1127, 1182, 1237, 1292)[zone - 1]
    if weight_oz <= 16:
        return (924, 979, 1034, 1089, 1144, 1199, 1254, 1309)[zone - 1]
    if weight_oz <= 20:
        return (941, 996, 1051, 1106, 1161, 1216, 1271, 1326)[zone - 1]
    if weight_oz <= 24:
        return (958, 1013, 1068, 1123, 1178, 1233, 1288, 1343)[zone - 1]
    if weight_oz <= 32:
        return (975, 1030, 1085, 1140, 1195, 1250, 1305, 1360)[zone - 1]
    if weight_oz <= 40:
        return (992, 1047, 1102, 1157, 1212, 1267, 1322, 1377)[zone - 1]
    if weight_oz <= 48:
        return (1009, 1064, 1119, 1174, 1229, 1284, 1339, 1394)[zone - 1]
    if weight_oz <= 56:
        return (1026, 1081, 1136, 1191, 1246, 1301, 1356, 1411)[zone - 1]
    if weight_oz <= 64:
        return (1043, 1098, 1153, 1208, 1263, 1318, 1373, 1428)[zone - 1]
    if weight_oz <= 72:
        return (1060, 1115, 1170, 1225, 1280, 1335, 1390, 1445)[zone - 1]
    if weight_oz <= 80:
        return (1077, 1132, 1187, 1242, 1297, 1352, 1407, 1462)[zone - 1]
    if weight_oz <= 96:
        return (1094, 1149, 1204, 1259, 1314, 1369, 1424, 1479)[zone - 1]
    if weight_oz <= 112:
        return (1111, 1166, 1221, 1276, 1331, 1386, 1441, 1496)[zone - 1]
    if weight_oz <= 128:
        return (1128, 1183, 1238, 1293, 1348, 1403, 1458, 1513)[zone - 1]
    if weight_oz <= 160:
        return (1145, 1200, 1255, 1310, 1365, 1420, 1475, 1530)[zone - 1]
    if weight_oz <= 192:
        return (1162, 1217, 1272, 1327, 1382, 1437, 1492, 1547)[zone - 1]
    if weight_oz <= 224:
        return (1179, 1234, 1289, 1344, 1399, 1454, 1509, 1564)[zone - 1]
    if weight_oz <= 256:
        return (1196, 1251, 1306, 1361, 1416, 1471, 1526, 1581)[zone - 1]
    if weight_oz <= 320:
        return (1213, 1268, 1323, 1378, 1433, 1488, 1543, 1598)[zone - 1]
    if weight_oz <= 384:
        return (1230, 1285, 1340, 1395, 1450, 1505, 1560, 1615)[zone - 1]
    if weight_oz <= 448:
        return (1247, 1302, 1357, 1412, 1467, 1522, 1577, 1632)[zone - 1]
    if weight_oz <= 512:
        return (1264, 1319, 1374, 1429, 1484, 1539, 1594, 1649)[zone - 1]
    if weight_oz <= 640:
        return (1281, 1336, 1391, 1446, 1501, 1556, 1611, 1666)[zone - 1]
    if weight_oz <= 768:
        return (1298, 1353, 1408, 1463, 1518, 1573, 1628, 1683)[zone - 1]
    if weight_oz <= 896:
        return (1315, 1370, 1425, 1480, 1535, 1590, 1645, 1700)[zone - 1]
    if weight_oz <= 1024:
        return (1332, 1387, 1442, 1497, 1552, 1607, 1662, 1717)[zone - 1]
    if weight_oz <= 1280:
        return (1349, 1404, 1459, 1514, 1569, 1624, 1679, 1734)[zone - 1]
    if weight_oz <= 1536:
        return (1366, 1421, 1476, 1531, 1586, 1641, 1696, 1751)[zone - 1]
    if weight_oz <= 1792:
        return (1383, 1438, 1493, 1548, 1603, 1658, 1713, 1768)[zone - 1]
    if weight_oz <= 2048:
        return (1400, 1455, 1510, 1565, 1620, 1675, 1730, 1785)[zone - 1]
    if weight_oz <= 2560:
        return (1417, 1472, 1527, 1582, 1637, 1692, 1747, 1802)[zone - 1]
    if weight_oz <= 3072:
        return (1434, 1489, 1544, 1599, 1654, 1709, 1764, 1819)[zone - 1]
    if weight_oz <= 3584:
        return (1451, 1506, 1561, 1616, 1671, 1726, 1781, 1836)[zone - 1]
    if weight_oz <= 4096:
        return (1468, 1523, 1578, 1633, 1688, 1743, 1798, 1853)[zone - 1]
    if weight_oz <= 4608:
        return (1485, 1540, 1595, 1650, 1705, 1760, 1815, 1870)[zone - 1]
    if weight_oz <= 5120:
        return (1502, 1557, 1612, 1667, 1722, 1777, 1832, 1887)[zone - 1]
    raise ValueError("weight exceeds published express tariff")


def priority_base_cents(zone: int, weight_oz: int) -> int:
    if not 1 <= zone <= 8:
        raise ValueError(f"zone out of range: {zone}")
    if weight_oz < 1:
        raise ValueError("weight must be positive")
    if weight_oz <= 8:
        return (1240, 1310, 1380, 1450, 1520, 1590, 1660, 1730)[zone - 1]
    if weight_oz <= 12:
        return (1257, 1327, 1397, 1467, 1537, 1607, 1677, 1747)[zone - 1]
    if weight_oz <= 16:
        return (1274, 1344, 1414, 1484, 1554, 1624, 1694, 1764)[zone - 1]
    if weight_oz <= 20:
        return (1291, 1361, 1431, 1501, 1571, 1641, 1711, 1781)[zone - 1]
    if weight_oz <= 24:
        return (1308, 1378, 1448, 1518, 1588, 1658, 1728, 1798)[zone - 1]
    if weight_oz <= 32:
        return (1325, 1395, 1465, 1535, 1605, 1675, 1745, 1815)[zone - 1]
    if weight_oz <= 40:
        return (1342, 1412, 1482, 1552, 1622, 1692, 1762, 1832)[zone - 1]
    if weight_oz <= 48:
        return (1359, 1429, 1499, 1569, 1639, 1709, 1779, 1849)[zone - 1]
    if weight_oz <= 56:
        return (1376, 1446, 1516, 1586, 1656, 1726, 1796, 1866)[zone - 1]
    if weight_oz <= 64:
        return (1393, 1463, 1533, 1603, 1673, 1743, 1813, 1883)[zone - 1]
    if weight_oz <= 72:
        return (1410, 1480, 1550, 1620, 1690, 1760, 1830, 1900)[zone - 1]
    if weight_oz <= 80:
        return (1427, 1497, 1567, 1637, 1707, 1777, 1847, 1917)[zone - 1]
    if weight_oz <= 96:
        return (1444, 1514, 1584, 1654, 1724, 1794, 1864, 1934)[zone - 1]
    if weight_oz <= 112:
        return (1461, 1531, 1601, 1671, 1741, 1811, 1881, 1951)[zone - 1]
    if weight_oz <= 128:
        return (1478, 1548, 1618, 1688, 1758, 1828, 1898, 1968)[zone - 1]
    if weight_oz <= 160:
        return (1495, 1565, 1635, 1705, 1775, 1845, 1915, 1985)[zone - 1]
    if weight_oz <= 192:
        return (1512, 1582, 1652, 1722, 1792, 1862, 1932, 2002)[zone - 1]
    if weight_oz <= 224:
        return (1529, 1599, 1669, 1739, 1809, 1879, 1949, 2019)[zone - 1]
    if weight_oz <= 256:
        return (1546, 1616, 1686, 1756, 1826, 1896, 1966, 2036)[zone - 1]
    if weight_oz <= 320:
        return (1563, 1633, 1703, 1773, 1843, 1913, 1983, 2053)[zone - 1]
    if weight_oz <= 384:
        return (1580, 1650, 1720, 1790, 1860, 1930, 2000, 2070)[zone - 1]
    if weight_oz <= 448:
        return (1597, 1667, 1737, 1807, 1877, 1947, 2017, 2087)[zone - 1]
    if weight_oz <= 512:
        return (1614, 1684, 1754, 1824, 1894, 1964, 2034, 2104)[zone - 1]
    if weight_oz <= 640:
        return (1631, 1701, 1771, 1841, 1911, 1981, 2051, 2121)[zone - 1]
    if weight_oz <= 768:
        return (1648, 1718, 1788, 1858, 1928, 1998, 2068, 2138)[zone - 1]
    if weight_oz <= 896:
        return (1665, 1735, 1805, 1875, 1945, 2015, 2085, 2155)[zone - 1]
    if weight_oz <= 1024:
        return (1682, 1752, 1822, 1892, 1962, 2032, 2102, 2172)[zone - 1]
    if weight_oz <= 1280:
        return (1699, 1769, 1839, 1909, 1979, 2049, 2119, 2189)[zone - 1]
    if weight_oz <= 1536:
        return (1716, 1786, 1856, 1926, 1996, 2066, 2136, 2206)[zone - 1]
    if weight_oz <= 1792:
        return (1733, 1803, 1873, 1943, 2013, 2083, 2153, 2223)[zone - 1]
    if weight_oz <= 2048:
        return (1750, 1820, 1890, 1960, 2030, 2100, 2170, 2240)[zone - 1]
    if weight_oz <= 2560:
        return (1767, 1837, 1907, 1977, 2047, 2117, 2187, 2257)[zone - 1]
    if weight_oz <= 3072:
        return (1784, 1854, 1924, 1994, 2064, 2134, 2204, 2274)[zone - 1]
    if weight_oz <= 3584:
        return (1801, 1871, 1941, 2011, 2081, 2151, 2221, 2291)[zone - 1]
    if weight_oz <= 4096:
        return (1818, 1888, 1958, 2028, 2098, 2168, 2238, 2308)[zone - 1]
    if weight_oz <= 4608:
        return (1835, 1905, 1975, 2045, 2115, 2185, 2255, 2325)[zone - 1]
    if weight_oz <= 5120:
        return (1852, 1922, 1992, 2062, 2132, 2202, 2272, 2342)[zone - 1]
    raise ValueError("weight exceeds published priority tariff")


def overnight_base_cents(zone: int, weight_oz: int) -> int:
    if not 1 <= zone <= 8:
        raise ValueError(f"zone out of range: {zone}")
    if weight_oz < 1:
        raise ValueError("weight must be positive")
    if weight_oz <= 8:
        return (1890, 1980, 2070, 2160, 2250, 2340, 2430, 2520)[zone - 1]
    if weight_oz <= 12:
        return (1907, 1997, 2087, 2177, 2267, 2357, 2447, 2537)[zone - 1]
    if weight_oz <= 16:
        return (1924, 2014, 2104, 2194, 2284, 2374, 2464, 2554)[zone - 1]
    if weight_oz <= 20:
        return (1941, 2031, 2121, 2211, 2301, 2391, 2481, 2571)[zone - 1]
    if weight_oz <= 24:
        return (1958, 2048, 2138, 2228, 2318, 2408, 2498, 2588)[zone - 1]
    if weight_oz <= 32:
        return (1975, 2065, 2155, 2245, 2335, 2425, 2515, 2605)[zone - 1]
    if weight_oz <= 40:
        return (1992, 2082, 2172, 2262, 2352, 2442, 2532, 2622)[zone - 1]
    if weight_oz <= 48:
        return (2009, 2099, 2189, 2279, 2369, 2459, 2549, 2639)[zone - 1]
    if weight_oz <= 56:
        return (2026, 2116, 2206, 2296, 2386, 2476, 2566, 2656)[zone - 1]
    if weight_oz <= 64:
        return (2043, 2133, 2223, 2313, 2403, 2493, 2583, 2673)[zone - 1]
    if weight_oz <= 72:
        return (2060, 2150, 2240, 2330, 2420, 2510, 2600, 2690)[zone - 1]
    if weight_oz <= 80:
        return (2077, 2167, 2257, 2347, 2437, 2527, 2617, 2707)[zone - 1]
    if weight_oz <= 96:
        return (2094, 2184, 2274, 2364, 2454, 2544, 2634, 2724)[zone - 1]
    if weight_oz <= 112:
        return (2111, 2201, 2291, 2381, 2471, 2561, 2651, 2741)[zone - 1]
    if weight_oz <= 128:
        return (2128, 2218, 2308, 2398, 2488, 2578, 2668, 2758)[zone - 1]
    if weight_oz <= 160:
        return (2145, 2235, 2325, 2415, 2505, 2595, 2685, 2775)[zone - 1]
    if weight_oz <= 192:
        return (2162, 2252, 2342, 2432, 2522, 2612, 2702, 2792)[zone - 1]
    if weight_oz <= 224:
        return (2179, 2269, 2359, 2449, 2539, 2629, 2719, 2809)[zone - 1]
    if weight_oz <= 256:
        return (2196, 2286, 2376, 2466, 2556, 2646, 2736, 2826)[zone - 1]
    if weight_oz <= 320:
        return (2213, 2303, 2393, 2483, 2573, 2663, 2753, 2843)[zone - 1]
    if weight_oz <= 384:
        return (2230, 2320, 2410, 2500, 2590, 2680, 2770, 2860)[zone - 1]
    if weight_oz <= 448:
        return (2247, 2337, 2427, 2517, 2607, 2697, 2787, 2877)[zone - 1]
    if weight_oz <= 512:
        return (2264, 2354, 2444, 2534, 2624, 2714, 2804, 2894)[zone - 1]
    if weight_oz <= 640:
        return (2281, 2371, 2461, 2551, 2641, 2731, 2821, 2911)[zone - 1]
    if weight_oz <= 768:
        return (2298, 2388, 2478, 2568, 2658, 2748, 2838, 2928)[zone - 1]
    if weight_oz <= 896:
        return (2315, 2405, 2495, 2585, 2675, 2765, 2855, 2945)[zone - 1]
    if weight_oz <= 1024:
        return (2332, 2422, 2512, 2602, 2692, 2782, 2872, 2962)[zone - 1]
    if weight_oz <= 1280:
        return (2349, 2439, 2529, 2619, 2709, 2799, 2889, 2979)[zone - 1]
    if weight_oz <= 1536:
        return (2366, 2456, 2546, 2636, 2726, 2816, 2906, 2996)[zone - 1]
    if weight_oz <= 1792:
        return (2383, 2473, 2563, 2653, 2743, 2833, 2923, 3013)[zone - 1]
    if weight_oz <= 2048:
        return (2400, 2490, 2580, 2670, 2760, 2850, 2940, 3030)[zone - 1]
    if weight_oz <= 2560:
        return (2417, 2507, 2597, 2687, 2777, 2867, 2957, 3047)[zone - 1]
    if weight_oz <= 3072:
        return (2434, 2524, 2614, 2704, 2794, 2884, 2974, 3064)[zone - 1]
    if weight_oz <= 3584:
        return (2451, 2541, 2631, 2721, 2811, 2901, 2991, 3081)[zone - 1]
    if weight_oz <= 4096:
        return (2468, 2558, 2648, 2738, 2828, 2918, 3008, 3098)[zone - 1]
    if weight_oz <= 4608:
        return (2485, 2575, 2665, 2755, 2845, 2935, 3025, 3115)[zone - 1]
    if weight_oz <= 5120:
        return (2502, 2592, 2682, 2772, 2862, 2952, 3042, 3132)[zone - 1]
    raise ValueError("weight exceeds published overnight tariff")


def additional_handling_cents(weight_oz: int, length_in: int, width_in: int, height_in: int) -> int:
    longest = max(length_in, width_in, height_in)
    if weight_oz > 50 * 16:
        return 2475
    if longest > 48:
        return 1975
    if girth_inches(length_in, width_in, height_in) > 105:
        return 1975
    return 0


def large_package_cents(length_in: int, width_in: int, height_in: int) -> int:
    girth = girth_inches(length_in, width_in, height_in)
    longest = max(length_in, width_in, height_in)
    if longest > 96 or girth > 130:
        return 15500
    if girth > 105:
        return 8750
    return 0


def residential_cents(residential: bool, service: str) -> int:
    if not residential:
        return 0
    if service == "overnight":
        return 650
    if service == "priority":
        return 545
    if service == "express":
        return 480
    return 375


def delivery_area_cents(zone: int, residential: bool) -> int:
    if zone < 7:
        return 0
    base = 420 if zone == 7 else 610
    if residential:
        return base + 180
    return base


def signature_cents(signature: str) -> int:
    kind = signature.strip().lower()
    if kind in {"", "none"}:
        return 0
    if kind == "standard":
        return 650
    if kind == "adult":
        return 850
    raise ValueError(f"unknown signature option {signature}")


def saturday_cents(saturday: bool, service: str) -> int:
    if not saturday:
        return 0
    if service == "ground":
        raise ValueError("ground has no saturday delivery")
    return 1650


def fuel_cents(base_cents: int, service: str) -> int:
    if service == "overnight":
        bps = 1450
    elif service == "priority":
        bps = 1325
    elif service == "express":
        bps = 1200
    else:
        bps = 975
    return (base_cents * bps) // 10000


def insurance_cents(declared_value_cents: int) -> int:
    if declared_value_cents < 0:
        raise ValueError("declared value cannot be negative")
    if declared_value_cents <= 10000:
        return 0
    blocks = (declared_value_cents - 10000 + 9999) // 10000
    return blocks * 115


def discount_cents(base_cents: int, service: str, weight_oz: int) -> int:
    if weight_oz < 16 * 10:
        return 0
    if service == "ground":
        return base_cents // 20
    if service == "express":
        return base_cents // 25
    return 0


def transit_days(zone: int, service: str) -> int:
    if service == "overnight":
        return 1
    if service == "priority":
        return 2 if zone <= 4 else 3
    if service == "express":
        return 2 + zone // 3
    return 1 + zone


def peak_cents(service: str, month: int) -> int:
    if month < 1 or month > 12:
        raise ValueError(f"month out of range: {month}")
    if month not in {11, 12}:
        return 0
    if service == "overnight":
        return 450
    if service == "priority":
        return 325
    if service == "express":
        return 250
    return 175


def address_correction_cents(corrected: bool) -> int:
    if not corrected:
        return 0
    return 2100


def minimum_cents(service: str) -> int:
    if service == "overnight":
        return 2490
    if service == "priority":
        return 1490
    if service == "express":
        return 990
    return 450


def service_base_cents(service: str, zone: int, weight_oz: int) -> int:
    if service == "ground":
        return ground_base_cents(zone, weight_oz)
    if service == "express":
        return express_base_cents(zone, weight_oz)
    if service == "priority":
        return priority_base_cents(zone, weight_oz)
    return overnight_base_cents(zone, weight_oz)


def build_quote(
    dest_zip: str,
    weight_oz: int,
    length_in: int,
    width_in: int,
    height_in: int,
    service: str,
    residential: bool,
    signature: str,
    saturday: bool,
    declared_value_cents: int,
    month: int,
    address_corrected: bool,
) -> Quote:
    name = require_service(service)
    zone = zone_for_zip(dest_zip)
    billable = billable_oz(weight_oz, length_in, width_in, height_in, name)
    base = service_base_cents(name, zone, billable)
    fuel = fuel_cents(base, name)
    surcharge = 0
    surcharge += additional_handling_cents(billable, length_in, width_in, height_in)
    surcharge += large_package_cents(length_in, width_in, height_in)
    surcharge += residential_cents(residential, name)
    surcharge += delivery_area_cents(zone, residential)
    surcharge += signature_cents(signature)
    surcharge += saturday_cents(saturday, name)
    surcharge += insurance_cents(declared_value_cents)
    surcharge += peak_cents(name, month)
    surcharge += address_correction_cents(address_corrected)
    discount = discount_cents(base, name, billable)
    total = base + fuel + surcharge - discount
    floor = minimum_cents(name)
    if total < floor:
        total = floor
    return Quote(
        service=name,
        zone=zone,
        billable_oz=billable,
        base_cents=base,
        fuel_cents=fuel,
        surcharge_cents=surcharge,
        discount_cents=discount,
        total_cents=total,
        transit_days=transit_days(zone, name),
    )
