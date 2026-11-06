# Healthcare: discovery questions

Add these to the standard [discovery questionnaire](../../../../partner-pack/discovery-questionnaire.md).

| # | Question | Who answers | Feeds |
|---|---|---|---|
| H1 | What does the agent do: booking, symptom triage, care-team support, discharge, claims? Does it give clinical advice? | Clinical lead | Purposes; risk |
| H2 | How long are indoor, outpatient, diagnostic and medico-legal records kept, under which state rules and hospital policy? | Medical records, counsel | `clinical_records` hold |
| H3 | Are children treated? Who consents for them? | Clinical lead, counsel | Out of scope today (s.9); plan a manual process |
| H4 | Is the hospital an ABDM HIP / HIU? Where are consent artefacts and linked care contexts stored? | Medical records | `abdm_linking`; inventory |
| H5 | Which labs, insurers, TPAs, pharmacies and telemedicine partners receive data? | Procurement, legal | `rights.recipients`; processor register |
| H6 | Who are caregivers / attendants in records, and how are their contact details captured? | Nursing, front office | Identifiers; redaction |
| H7 | What do UHID, MRN, IP and OP numbers look like? | Medical records | `pii.patterns` |
| H8 | Which languages do patients write in, and what NER or LLM detector is approved for clinical text? | Clinical informatics, security | `pii.detectors`; A10 sample |
