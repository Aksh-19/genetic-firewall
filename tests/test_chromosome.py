from src.ga.chromosome import Chromosome


def test_chromosome_initialization():
    genes = [0, 1, 1, 0, 1]
    chrom = Chromosome(genes)
    assert chrom.genes == genes
    assert len(chrom) == 5
    assert chrom.fitness is None


def test_chromosome_random():
    length = 20
    chrom = Chromosome.random(length)
    assert len(chrom) == length
    assert all(gene in (0, 1) for gene in chrom.genes)


def test_chromosome_copy():
    chrom = Chromosome([1, 0, 1])
    chrom.fitness = 42.0
    clone = chrom.copy()
    assert clone.genes == chrom.genes
    assert clone.fitness == 42.0
    # Ensure deep copy of genes list
    clone.genes[0] = 0
    assert chrom.genes[0] == 1
