import hashlib
from typing import List, Optional


def merkle_root(hashes: List[str]) -> Optional[str]:
    """
    Строит Merkle root из списка hex-хэшей.
    Если список пуст — возвращает None.
    Если один элемент — он и есть корень.
    """
    if not hashes:
        return None
    level = [h for h in hashes]
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            data = (left + right).encode()
            next_level.append(hashlib.sha256(data).hexdigest())
        level = next_level
    return level[0]


def merkle_path(hashes: List[str], index: int) -> List[str]:
    """
    Вернуть список sibling-хэшей от листа до корня (без самого листа).
    """
    if not hashes or index < 0 or index >= len(hashes):
        return []
    path = []
    level = [h for h in hashes]
    idx = index
    while len(level) > 1:
        next_level = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else left
            data = (left + right).encode()
            next_level.append(hashlib.sha256(data).hexdigest())
            if i == idx or i + 1 == idx:
                sibling = right if i == idx else left
                path.append(sibling)
        idx = idx // 2
        level = next_level
    return path
