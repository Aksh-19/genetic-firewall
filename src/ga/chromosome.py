import random
from typing import List, Optional


class Chromosome:
    """
    Represents a single individual's DNA strand.
    In Phase 2, this is a sequence of binary bits (0s and 1s).
    """

    def __init__(self, genes: List[int]):
        self.genes = list(genes)
        self.fitness: Optional[float] = None

    @classmethod
    def random(cls, length: int) -> "Chromosome":
        """Creates a chromosome initialized with random 0s and 1s."""
        genes = [random.randint(0, 1) for _ in range(length)]
        return cls(genes)

    def copy(self) -> "Chromosome":
        """Creates an exact clone of this chromosome."""
        clone = Chromosome(self.genes)
        clone.fitness = self.fitness
        return clone

    def __len__(self) -> int:
        return len(self.genes)

    def __repr__(self) -> str:
        gene_str = "".join(str(g) for g in self.genes)
        preview = gene_str[:12] + ("..." if len(gene_str) > 12 else "")
        return f"Chromosome(len={len(self.genes)}, fitness={self.fitness}, genes='{preview}')"
