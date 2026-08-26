from __future__ import annotations


# Canonical native-code defect families routed to the fuzz engineer. Keep this
# policy shared by fuzz forcing and finding-mutation guards so a relabel cannot
# create a gap between the two enforcement points.
NATIVE_MEMORY_SAFETY_DEFECT_FAMILIES = frozenset(
    {
        "buffer-overflow",
        "format-string",
        "integer-overflow",
        "null-dereference",
        "type-confusion",
        "uninitialized-memory",
        "use-after-free",
    }
)
