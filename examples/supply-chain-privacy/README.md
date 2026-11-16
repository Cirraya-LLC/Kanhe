# Supply-chain privacy

Who sees what along a supply chain. A core enterprise (A) owes its tier-1 supplier (B)
CNY 1,000,000, payable at maturity. B orders parts from its own supplier (C) for
CNY 400,000. B does not want C to learn that it supplies A; a bank should see everything, so
that it can pay C early against A's promise. Four organizations, four ledgers.

What it shows:

- **Two agreements, each between its two parties.** The receivable is on A's ledger, under
  [`receivable.bo`](receivable.bo) (the receivable-financing example's terms). B's order to C
  is a record on B's own ledger.
- **Fields disclosed one by one.** The order's fields are private: the ledger keeps salted
  commitments, B's vault the values. C receives the order's evidence with the goods, amount,
  due date, and supplier disclosed; `backed_by`, which names A's receivable, stays sealed. The
  script checks that nothing in C's copy, nor anything on C's ledger, names A: not its name,
  not its ledger id, not the receivable. C can see that the order has one more field, never
  what it holds.
- **A source on another ledger.** C accepts the order on its own ledger, naming B's order as
  its source and keeping B's evidence as the proof.
- **Everything, for the bank.** B gives Bank A the order with `backed_by` disclosed, and the
  receivable's evidence from A's ledger. Bank A verifies both offline, checks that the order
  names that receivable and that B holds it unpledged, and consents to B's pledge of it.
- **One financing at a time.** A pledged receivable cannot be pledged again, so it backs one
  facility only.
- **What a consent says travels.** A consent's reference is kept, with its evidence, on A's
  ledger: B's and Bank A's name the facility, never C or the order. (A first draft of this
  script named the order there; its own check caught it.)
- **What A sees.** Its receivable, pledged to Bank A. Nothing on A's ledger names C or the
  order.

The other way to finance a supply chain is in [multi-tier-split](../multi-tier-split/): there
the core enterprise's receivable is split into parts that it pays itself at maturity, so each
holder relies on A's promise directly, and the parts, on A's ledger, show who holds them. Here
C relies on B, and only the bank sees the whole chain.

```sh
bo test examples/supply-chain-privacy/receivable.bo
examples/supply-chain-privacy/supply-chain-privacy.sh [KANHE] [DIR]   # CTest: demo_supply_chain_privacy
```
