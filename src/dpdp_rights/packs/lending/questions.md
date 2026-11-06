# Lending: discovery questions

Add these to the standard [discovery questionnaire](../../../../partner-pack/discovery-questionnaire.md).

| # | Question | Who answers | Feeds |
|---|---|---|---|
| L1 | Is the client a bank, NBFC, or LSP working for one? Which digital lending apps are reported to RBI? | Compliance | Scope; processor roles |
| L2 | Which data does the app collect, and is any device data (contacts, call logs, media, location) accessed? | Product, security | Inventory; Digital Lending Directions check |
| L3 | Where is borrower data stored and processed? Any processing outside India? | Platform | Inventory regions; coverage findings |
| L4 | When is a loan account "closed" for record keeping, and how long are loan files and KYC records kept? | Compliance, counsel | `loan_account`, `kyc_aml` holds |
| L5 | Which bureaus, co-lenders, collection agencies and LSPs receive data, under which contracts? | Procurement, legal | `rights.recipients`; processor register |
| L6 | How are corrections to data already reported to a bureau handled? | Operations | Correction follow-ups |
| L7 | What do loan account and application numbers look like? | Operations | `pii.patterns` |
| L8 | Are collections calls recorded, by whom, and where? | Collections | Inventory; manual procedures |
