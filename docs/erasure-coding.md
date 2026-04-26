# Erasure Coding in Object Storage

## Introduction

Erasure coding is a data protection technique that splits data into fragments, expands those fragments with redundant parity pieces, and stores all the pieces across distinct locations. If some pieces are lost or corrupted, the original data can be reconstructed from the surviving fragments alone -- without needing a full second copy. This makes erasure coding far more storage-efficient than simple replication while providing comparable or superior fault tolerance.

The most widely deployed family of erasure codes is **Reed-Solomon** (RS), introduced by Irving S. Reed and Gustave Solomon in 1960. Reed-Solomon codes underpin an enormous range of systems: CDs, DVDs, Blu-ray discs, QR codes, DSL, satellite communications, RAID 6, and virtually every major cloud object storage platform. When a cloud provider claims "eleven nines of durability," erasure coding is almost certainly part of how they deliver it.

### A Concrete Example: CDs

Compact discs can recover from scratches that corrupt up to 4,000 consecutive bits (roughly 2.5 mm of disc surface). They achieve this through Cross-Interleaved Reed-Solomon Coding (CIRC), which layers two RS codes with cross-wise interleaving. An inner (32,28) RS code corrects small errors and flags anything it cannot fix as an erasure. A deinterleaver spreads those erasures across blocks of an outer (28,24) RS code, which can correct up to 4 erasures per block. The result: most CD playback failures are caused by tracking problems, not uncorrectable data corruption.

## Key Concepts

### Finite Fields and Why They Matter

Reed-Solomon codes operate over finite fields (also called Galois fields), most commonly GF(2^8) -- the field of 256 elements that maps naturally to bytes. Finite field arithmetic guarantees that every non-zero element has a multiplicative inverse, which is what allows the decoder to solve the polynomial equations needed for interpolation and error location without ambiguity. A practical benefit of GF(2^8) is that addition reduces to XOR, making both hardware and software implementations very fast.

### The k-of-n Survival Rule

An RS(n, k) code encodes k data symbols into n total symbols (k data + r parity, where r = n - k). The fundamental property:

> Any k of the n total symbols are sufficient to reconstruct the original data.

This means you can lose any r symbols and still recover everything. The value r is the "tolerance budget" -- the maximum number of simultaneous failures the system can absorb.

### Errors vs. Erasures

The distinction between errors and erasures is critical for understanding RS code performance:

- **Erasure**: A symbol is missing or known to be bad (e.g., a failed disk, a dropped network packet). The decoder only needs to fill in the blank. An RS code with r parity symbols can correct up to r erasures.
- **Error**: A symbol is corrupted but you do not know which one. The decoder must both locate and correct it, which costs twice as many parity symbols. The same code can correct only r/2 errors at unknown locations.

This asymmetry is why production storage systems almost always pair erasure coding with checksums: by detecting which blocks are corrupt, checksums convert errors into erasures, doubling the effective correction capacity.

### Systematic Codes

In a systematic RS code, the original data symbols appear unmodified in the output, with parity symbols appended. This means reads that do not encounter failures can return data directly without decoding -- an important performance optimization for storage systems where the common case is that nothing is broken.

## Parameter Trade-Offs

The choice of k (data shards) and r (parity shards) is the central design decision in any erasure-coded storage system. The trade-off is straightforward:

- **More parity (larger r)**: Higher fault tolerance, but more storage overhead and higher repair bandwidth when a shard is lost.
- **More data shards (larger k)**: Better storage efficiency, but each individual shard is a smaller fraction of the whole, increasing the minimum number of pieces needed for reconstruction.

### Real-World Parameters

| Code (k + r) | Storage Overhead | Max Simultaneous Failures | Example Deployment |
|---|---|---|---|
| 17 + 3 | 1.18x | 3 | Backblaze B2 |
| 10 + 4 | 1.4x | 4 | Facebook HDFS cold storage |
| 8 + 4 | 1.5x | 4 | OVH Cloud |
| 6 + 3 | 1.5x | 3 | Scaleway |

For comparison, simple 3-way replication uses 3.0x storage overhead to tolerate 2 failures. Even a conservative erasure coding scheme like 6+3 matches that fault tolerance at half the storage cost.

### Heuristics for Choosing (k, r)

- Start with your expected failure rate and recovery time target. If disk replacement takes hours, you need enough parity to survive overlapping failures during that window.
- r should generally be at least 2. A single parity shard (r=1) means any single failure during a rebuild is fatal.
- Larger k improves storage efficiency but increases the amount of data that must be read to repair a single lost shard (repair bandwidth). For very large k, this can become a bottleneck.
- Match parity to actual failure-mode analysis, not gut feel. Correlated failures (e.g., an entire rack losing power, a firmware bug affecting a batch of drives) can take out multiple shards simultaneously.

## Erasure Coding in Managed Object Storage Providers

Managed S3-compatible storage providers handle erasure coding transparently. Users upload and download objects through the S3 API; the provider is responsible for encoding, distributing shards, repairing failures, and maintaining durability guarantees. From the application's perspective, the object is simply stored and available.

### Amazon S3

Amazon S3 claims 99.999999999% (eleven nines) durability for the Standard storage class. AWS has not publicly disclosed the specific erasure coding parameters they use, but it is widely understood to be Reed-Solomon or a close variant, with data distributed across multiple facilities within a region. S3 is the de facto API standard that other providers emulate.

### Backblaze B2

Backblaze has been unusually transparent about their storage architecture. B2 uses a 17+3 Reed-Solomon code, meaning 17 data shards and 3 parity shards. This yields only 1.18x storage overhead while tolerating up to 3 simultaneous shard failures. Backblaze publishes detailed drive failure statistics annually, providing one of the best public datasets on storage hardware reliability. B2 offers an S3-compatible API alongside its native API.

### Wasabi Cloud Storage

Wasabi provides S3-compatible hot cloud storage with a focus on low cost and simplicity (no egress fees, no API request fees). Wasabi claims eleven nines of durability. While they have not published their exact erasure coding parameters, their architecture stores data redundantly across multiple availability zones within a region. Wasabi uses immutable storage buckets as a differentiator, offering built-in protection against ransomware and accidental deletion. All data is encrypted at rest. Wasabi requires path-style S3 addressing, which is a relevant integration detail for applications using generic S3 client libraries.

### Cloudflare R2

Cloudflare R2 is an S3-compatible object storage service designed to eliminate egress fees. R2 stores data across Cloudflare's global network of data centers, providing geographic distribution as part of its default storage model rather than as an add-on tier. While Cloudflare has not published specific erasure coding parameters, the multi-datacenter distribution provides inherent redundancy. R2's S3 compatibility and zero egress pricing make it an attractive secondary or tertiary storage target for applications that need to read data frequently or serve it to end users.

## Erasure Coding in Self-Hosted and Open-Source Object Storage

Self-hosted storage gives operators direct control over erasure coding parameters, replication topology, and failure domains. This control comes with the responsibility of managing the storage infrastructure, monitoring for failures, and performing repairs.

### SeaweedFS

SeaweedFS is an open-source distributed storage system that provides an S3-compatible API. It supports configurable erasure coding at the volume level using Reed-Solomon codes. Operators can choose their data/parity ratio based on their hardware layout and fault tolerance requirements. SeaweedFS applies erasure coding to sealed (read-only) volumes, meaning recently written data may still be in replicated form until the volume is sealed and EC-encoded. This is a common pattern in append-oriented storage systems. SeaweedFS is written in Go and designed to be lightweight enough to run on modest hardware, making it suitable for self-hosted deployments where a full-scale distributed storage system like Ceph would be overkill.

### Ceph (RADOS)

Ceph is a mature, widely deployed open-source distributed storage system that supports erasure coding as a storage pool type. Ceph uses pluggable erasure coding profiles, with Reed-Solomon (via the Jerasure or ISA-L libraries) as the default. Operators define EC profiles specifying k and m (data and coding chunks), the plugin to use, and the failure domain (host, rack, datacenter). Ceph's EC pools are well-suited for cold or archival data; for latency-sensitive workloads, replicated pools are typically preferred. Ceph provides S3-compatible object storage through its RADOS Gateway (RGW) component.

## Azure Local Reconstruction Codes (LRC)

Microsoft Azure uses a variation of Reed-Solomon called Local Reconstruction Codes (LRC) for its storage infrastructure. Standard RS codes have a drawback: repairing a single lost shard requires reading k other shards, which is expensive in network bandwidth and I/O. LRC addresses this by adding local parity groups that can repair single failures within a small subset of shards, without needing to read the entire stripe. This significantly reduces the common-case repair cost while maintaining the full fault tolerance of global parity for multi-failure scenarios. Azure published their LRC design at USENIX ATC 2012, and it has since influenced erasure coding designs at other large-scale storage operators.

## Multi-Provider Redundancy vs. Erasure Coding

Erasure coding and multi-provider redundancy operate at different layers and protect against different categories of failure. They are complementary strategies, not alternatives.

**Erasure coding** operates within a single storage system. It protects against hardware failures (disk death, node outages, rack-level events) by distributing encoded shards across independent failure domains within that system. It is the provider's responsibility to implement and maintain.

**Multi-provider redundancy** operates at the application layer. It protects against provider-level failures: outages, policy changes, pricing changes, account suspension, data center disasters, or a provider ceasing operations entirely. It works by storing the same opaque blob (which may itself be erasure-coded internally by each provider) across two or more independent S3-compatible backends.

These two strategies are additive. A file stored on a provider that uses 17+3 RS internally is well-protected against hardware failure within that provider. The same file replicated to a second provider with its own internal erasure coding is additionally protected against the first provider becoming unavailable for any reason. Neither strategy makes the other redundant:

- EC alone does not help if the provider locks your account or goes offline.
- Multi-provider replication alone does not help if a bug in your application corrupts the blob before uploading it to all providers (both copies would be corrupt).

For systems that handle sensitive or long-lived data, combining both layers -- trusting each provider's internal durability guarantees while maintaining independent copies across providers -- offers the strongest practical protection against data loss.

## Common Pitfalls

- **Unequal shard sizes.** RS encoding requires all shards to be the same length. Data must be padded to a multiple of k before encoding. Forgetting this step is a common implementation bug.
- **Treating errors as erasures without verification.** If you do not checksum individual shards, you cannot reliably identify which ones are corrupt. Without that identification, the decoder must treat corruptions as errors rather than erasures, halving its correction capacity.
- **Choosing parity by gut feel.** Parity parameters should be derived from failure-mode analysis (expected failure rate, repair time, correlated failure risk), not from round numbers or intuition.
- **Ignoring repair bandwidth.** When a shard is lost, reconstruction requires reading k other shards from across the network. For large k values or frequent failures, this repair traffic can saturate network links and degrade performance for normal operations.

## References

### Introductory and Explanatory

- Backblaze: Reed-Solomon overview and implementation notes
  https://www.backblaze.com/blog/reed-solomon/
- Reed-Solomon for Programmers (bert hubert)
  https://berthub.eu/articles/posts/reed-solomon-for-programmers/
- Reed-Solomon error correction on CDs and in practice (Tom Verbeure)
  https://tomverbeure.github.io/2022/08/07/Reed-Solomon.html
- A practical first-principles guide to Reed-Solomon codes
  https://thelinuxcode.com/reedsolomon-codes-a-practical-firstprinciples-guide-for-modern-systems/

### Academic and Technical

- Wikipedia: Reed-Solomon error correction
  https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction
- Carnegie Mellon: Reed-Solomon codes in the real world
  https://www.cs.cmu.edu/~guyb/realworld/reedsolomon/reed_solomon_codes.html
- NASA Technical Report: Reed-Solomon coding
  https://ntrs.nasa.gov/api/citations/19900019023/downloads/19900019023.pdf
- Jerasure: A C library for erasure coding (USENIX FAST '12)
  https://www.usenix.org/conference/fast12/technical-sessions/presentation/plank

### Production Systems and Providers

- Erasure coding in production storage systems (survey)
  https://transactional.blog/blog/2024-erasure-coding
- Backblaze: Resiliency, durability, and availability
  https://www.backblaze.com/docs/cloud-storage-resiliency-durability-and-availability
- Ceph: Erasure coding documentation
  https://docs.ceph.com/en/latest/rados/operations/erasure-code/

### Libraries

- klauspost/reedsolomon: High-performance Reed-Solomon erasure coding in Go, with SIMD-accelerated operations
  https://github.com/klauspost/reedsolomon
