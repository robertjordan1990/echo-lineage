# Attribution and scope

This project is maintained under the project pseudonym **Robert Jordan**.
It was developed through documented human–AI collaboration within
**fAIR DecentrAIzation**, including implementation, documentation, test
preparation, and review.

Robert Jordan is a project pseudonym, not a separate person or legal entity.
The pseudonym does not create or receive copyright ownership. Copyright in
copyrightable contributions remains with their respective human contributors.
This attribution does not assign those rights to the pseudonym or an AI system.

The snapshot includes earlier project components, the Stage 2A read-only
verifier and a bounded Stage 2B Core implementation candidate. It makes no priority claim. A fresh publication history and its
publication date do not establish when the underlying work was first created
or independently invented.

Stage 2A runtime and tests use Python's standard library. Stage 2B uses
cryptography (Apache-2.0 OR BSD-3-Clause), with cffi (MIT) and pycparser (BSD-3-Clause)
in the tested environment; their own package notices and backend obligations
continue to apply. No third-party Python packages are vendored. The GitHub Actions workflow invokes
`actions/checkout` and `actions/setup-python`, which are separate dependencies.

All distributed identity, acceptance, handoff, and ledger examples are
fictional. They do not record current participants, installations, or decisions.

The Apache License, Version 2.0 is provided in [LICENSE](LICENSE). This notice
records attribution and does not modify the license terms.
